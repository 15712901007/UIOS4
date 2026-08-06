"""ICC 爱快云中心 云端操作工具(登录获取 token + 设备解绑 API).

用于"设备设置-云服务绑定"测试的云端解绑环节。路由器侧 register.sh 只能本地解绑
(cloud_async 清 register 表), 真正"从云账号移除设备"需调 ICC 平台 API:

    POST https://api.icc.ikuai8.com/v4/dm/devices/{gwid}/unbind
        Headers: Authorization: Bearer <token>, isAjax: 1, Content-Type: application/json
        Body:   {}

token 会过期, 每次测试重新获取。本工具用 Playwright 登录 icc.ikuai8.com(账号登录 tab,
无图形验证码; 短信登录才有滑块), 登录后从首个带 Authorization 头的请求抓取 Bearer token
(不依赖 localStorage key 名, 最可靠)。token 做实例级缓存, 重复调用不重复登录。
"""
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
)


class IccCloudHelper:
    """ICC 爱快云中心云端操作助手(登录 + 解绑)."""

    ICC_LOGIN_URL = "https://icc.ikuai8.com/#/login"
    API_BASE = "https://api.icc.ikuai8.com"
    DEFAULT_ACCOUNT = "sxrong@ikuai8.com"

    def __init__(self, page, account: str = DEFAULT_ACCOUNT, password: str = ""):
        """
        Args:
            page: 任意已存在的 Playwright Page(借用其 context 新开 page 登录 ICC,
                  不干扰被测路由器页面, ICC 的 localStorage/cookie 按 origin 隔离).
            account: ICC 账号(账号名/手机号).
            password: ICC 密码.
        """
        self.page = page
        self.account = account
        self.password = password
        self._token = None

    def login_get_token(self, timeout: int = 25) -> str:
        """登录 ICC 并返回 Bearer token。

        从(登录后或已登录页面)首个带 ``Authorization: Bearer`` 头的 API 请求抓取 token
        (ICC 的 token 不在 localStorage, 只在请求头)。已登录(context 已有 cookie)时
        跳过登录直接抓。token 实例级缓存, 重复调用直接返回。
        """
        if self._token:
            return self._token
        if not self.password:
            raise RuntimeError("ICC 密码未配置, 无法登录")

        icc_page = self.page.context.new_page()
        holder = {"token": None}

        def _on_request(req):
            if holder["token"]:
                return
            try:
                auth = req.headers.get("authorization") or ""
            except Exception:
                auth = ""
            if auth.startswith("Bearer "):
                holder["token"] = auth[len("Bearer "):].strip()

        icc_page.on("request", _on_request)
        try:
            icc_page.goto(self.ICC_LOGIN_URL, wait_until="domcontentloaded")
            try:
                icc_page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass
            icc_page.wait_for_timeout(1200)

            # 检测是否已登录(已登录则 URL 不含 /login 且无 #account) -> 跳过登录直接抓 token
            on_login = ("/login" in icc_page.url) or (icc_page.locator("#account").count() > 0)
            if on_login:
                # 等登录表单渲染完成再 fill(SPA 异步, 避免 fill 超时)
                try:
                    icc_page.locator("#account").first.wait_for(state="visible", timeout=10000)
                except Exception:
                    pass
                # 确保停在"账号登录" tab(非短信登录)
                try:
                    icc_page.locator(".ant-tabs-tab:has-text('账号登录')").first.click(timeout=2500)
                    icc_page.wait_for_timeout(200)
                except Exception:
                    pass
                icc_page.fill("#account", self.account)
                icc_page.fill("#password", self.password)
                # 勾选"我已阅读并接受"协议(账号登录需要同意用户协议/隐私政策)
                try:
                    agree = icc_page.locator(
                        ".ant-checkbox-wrapper:has-text('我已阅读'), label:has-text('我已阅读并接受')"
                    )
                    if agree.count() > 0:
                        cb = agree.first.locator("input[type='checkbox']")
                        if cb.count() > 0 and not cb.first.is_checked():
                            agree.first.click()
                            icc_page.wait_for_timeout(150)
                except Exception:
                    pass
                # 点登录按钮(页面有账号/短信两个登录按钮, 取可见第一个)
                icc_page.locator("button:has-text('登录'):visible").first.click()

            # 等 token(登录成功后 或 已登录页面加载都会发带 token 的 API 请求)
            deadline = time.time() + timeout
            while time.time() < deadline and not holder["token"]:
                icc_page.wait_for_timeout(300)

            # fallback: reload 触发请求再抓一次(token 只在请求头)
            if not holder["token"]:
                try:
                    icc_page.reload(wait_until="domcontentloaded")
                except Exception:
                    pass
                deadline2 = time.time() + 12
                while time.time() < deadline2 and not holder["token"]:
                    icc_page.wait_for_timeout(300)

            self._token = holder["token"]
            return self._token
        finally:
            try:
                icc_page.close()
            except Exception:
                pass

    def _headers(self, token: str = None) -> dict:
        return {
            "Authorization": f"Bearer {token or self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "isAjax": "1",
            "Referer": "https://icc.ikuai8.com/",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-mobile": "?0",
            "User-Agent": DEFAULT_USER_AGENT,
        }

    def unbind_device(self, gwid: str, token: str = None) -> dict:
        """ICC 云端解绑设备: POST /v4/dm/devices/{gwid}/unbind。

        Returns:
            {ok, status, code, message, raw}。ok=True 表示云端接受解绑请求
            (HTTP 200 且 code 为成功码 2000/0)。
        """
        token = token or self._token
        if not token:
            return {"ok": False, "status": 0, "message": "无 token, 未登录 ICC"}
        url = f"{self.API_BASE}/v4/dm/devices/{gwid}/unbind"
        try:
            resp = requests.post(url, headers=self._headers(token),
                                 json={}, timeout=20, verify=False)
        except Exception as e:
            return {"ok": False, "status": 0, "message": f"请求异常: {str(e)[:120]}"}
        data = {}
        try:
            data = resp.json()
        except Exception:
            pass
        code = data.get("code")
        message = data.get("message") or data.get("msg") or ""
        ok = resp.status_code == 200 and (code in (2000, 0, "2000", "0"))
        return {"ok": ok, "status": resp.status_code, "code": code,
                "message": message, "raw": data}

    # ==================== SD-WAN 云端组网 API ====================
    # 全部位于 yun.ikuai8.com/api/v3(ICC 登录的 Bearer token 跨域有效, 实测通过)。
    #   GET  sdwan/list                         -> 账号下所有 SD-WAN 网络(sdwan_list[])
    #   GET  sdwan/isOpened                     -> 账号是否开通 SD-WAN(status=1)
    #   GET  business/sd/network/show?sdwan_id= -> 网络详情含分组+成员(groups[].members[])
    #   POST business/sd/group/update           -> 增删成员(同一端点, members 数组差异)
    # 成员 id 即设备 GWID(32位hex)。加/删成员 = GET-then-update 保住其它成员。
    YUN_API_BASE = "https://yun.ikuai8.com/api/v3"
    _YUN_OK_CODES = (2000, 0, "2000", "0")

    def login(self, max_retries: int = 3) -> str:
        """登录 ICC 拿 token, 带重试应对阿里云滑块风控瞬时拦截(偶发返回"账号或密码错误")。"""
        last_err = None
        for _ in range(max(1, max_retries)):
            try:
                tok = self.login_get_token(timeout=30)
                if tok:
                    return tok
            except Exception as e:
                last_err = e
            time.sleep(1.5)
        if last_err:
            raise last_err
        return self._token

    def _yun_ok(self, resp, data) -> bool:
        code = data.get("code")
        return resp.status_code == 200 and (code is None or code in self._YUN_OK_CODES)

    def _yun_get(self, path: str, params: dict = None, token: str = None) -> dict:
        token = token or self._token
        if not token:
            return {"ok": False, "message": "无 token, 未登录 ICC"}
        url = f"{self.YUN_API_BASE}/{path.lstrip('/')}"
        try:
            resp = requests.get(url, headers=self._headers(token), params=params or {},
                                timeout=20, verify=False)
        except Exception as e:
            return {"ok": False, "message": f"请求异常: {str(e)[:120]}"}
        data = {}
        try:
            data = resp.json()
        except Exception:
            pass
        return {"ok": self._yun_ok(resp, data), "status": resp.status_code,
                "code": data.get("code"), "message": data.get("message") or "",
                "data": data.get("data", data), "raw": data}

    def _yun_post(self, path: str, json_body: dict = None, token: str = None) -> dict:
        token = token or self._token
        if not token:
            return {"ok": False, "message": "无 token, 未登录 ICC"}
        url = f"{self.YUN_API_BASE}/{path.lstrip('/')}"
        try:
            resp = requests.post(url, headers=self._headers(token), json=json_body or {},
                                 timeout=20, verify=False)
        except Exception as e:
            return {"ok": False, "message": f"请求异常: {str(e)[:120]}"}
        data = {}
        try:
            data = resp.json()
        except Exception:
            pass
        return {"ok": self._yun_ok(resp, data), "status": resp.status_code,
                "code": data.get("code"), "message": data.get("message") or "",
                "data": data.get("data", data), "raw": data}

    def is_sdwan_opened(self, token: str = None) -> dict:
        """账号是否已开通 SD-WAN。data={status:1,has_free:0}。"""
        return self._yun_get("sdwan/isOpened", token=token)

    def list_sdwan_networks(self, token: str = None) -> dict:
        """列出账号下所有 SD-WAN 网络。data={sdwan_list:[{id,sdwan_name,package_type_name,
        router_num,used_router_num,status,...}], total, member_status}。"""
        return self._yun_get("sdwan/list",
                             params={"page_size": 50, "current_page": 0, "keyword": ""},
                             token=token)

    def pick_usable_network(self, gwid: str, token: str = None) -> dict:
        """从 sdwan/list 选一个可用网络: status=1 且 used_router_num<router_num(有富余配额)。
        返回 {ok, sdwan_id, sdwan_name, ...}。不校验 gwid 是否已在成员(需 get_sdwan_network)。"""
        r = self.list_sdwan_networks(token=token)
        if not r.get("ok"):
            return {"ok": False, "message": r.get("message", "list 失败")}
        for net in (r.get("data") or {}).get("sdwan_list") or []:
            if net.get("status") == 1 and self._has_free_router_slot(net):
                return {"ok": True, "sdwan_id": net.get("id"),
                        "sdwan_name": net.get("sdwan_name"),
                        "package_type_name": net.get("package_type_name"),
                        "router_num": net.get("router_num"),
                        "used_router_num": net.get("used_router_num")}
        return {"ok": False, "message": "无可用网络(均无富余路由器配额)"}

    @staticmethod
    def _has_free_router_slot(net: dict) -> bool:
        try:
            return int(net.get("used_router_num", 0)) < int(net.get("router_num", 0))
        except Exception:
            return False

    def get_sdwan_network(self, sdwan_id, token: str = None) -> dict:
        """网络详情(含分组+成员)。GET business/sd/network/show?sdwan_id=X。
        data={id,sdwan_name,groups:[{id(=group_id),group_name,members:[{id(=GWID),remark,...}]}]}。"""
        return self._yun_get("business/sd/network/show", params={"sdwan_id": sdwan_id}, token=token)

    def get_default_group(self, sdwan_id, token: str = None) -> dict:
        """取网络首个分组(默认分组)的 group_id + members + 拓扑参数。"""
        r = self.get_sdwan_network(sdwan_id, token=token)
        if not r.get("ok"):
            return {"ok": False, "message": r.get("message", "show 失败")}
        groups = (r.get("data") or {}).get("groups") or []
        if not groups:
            return {"ok": False, "message": "网络无分组"}
        g = groups[0]
        return {"ok": True, "sdwan_id": sdwan_id, "group_id": g.get("id"),
                "group_name": g.get("group_name") or "默认分组",
                "members": g.get("members") or [],
                "topology_type": g.get("topology_type", 1),
                "layer2_network": g.get("layer2_network", 0)}

    @staticmethod
    def _member_for_update(m: dict, default_bandwidth=10) -> dict:
        """把 show 返回的富成员对象(或新建成员)转为 group/update 需要的最小 schema。
        保留 id/type, **原样保留 bandwidth**(不强制类型转换, 避免改动其它成员的带宽)。"""
        bw = m.get("bandwidth")
        if bw is None:
            bw = default_bandwidth
        return {"id": m.get("id"), "parent_id": m.get("parent_id"),
                "bandwidth": bw,
                "m_role": m.get("m_role") or m.get("role") or "",
                "relation_id": m.get("relation_id") or [],
                "group_tip": m.get("group_tip") or 0,
                "type": m.get("type") or "route"}

    def update_sdwan_group(self, sdwan_id, group_id, members, group_name="默认分组",
                           topology_type=1, access_type=4, allow_visavis=0,
                           layer2_network=0, token: str = None) -> dict:
        """POST business/sd/group/update —— 加/删成员同一端点, 传完整 members 数组。
        members 元素需为 update schema({_member_for_update 产出})。
        云端写操作偶发瞬时 server error, 失败时重试最多 3 次。"""
        body = {"sdwan_id": sdwan_id, "group_id": group_id,
                "topology_type": topology_type, "group_name": group_name,
                "access_type": access_type, "allow_visavis": allow_visavis,
                "members": members, "layer2_network": layer2_network}
        last = {"ok": False, "message": "未执行"}
        for _ in range(3):
            last = self._yun_post("business/sd/group/update", json_body=body, token=token)
            if last.get("ok"):
                return last
            time.sleep(2)  # 瞬时 server error 重试
        return last

    def add_sdwan_member(self, sdwan_id, group_id, gwid, existing_members,
                         default_bandwidth=10, token: str = None, **kw) -> dict:
        """把 gwid 加入分组(基于现有成员 GET-then-update, 不扰动其它成员)。
        新成员带宽沿用首个现有成员的带宽(与网络套餐一致)。"""
        members = [self._member_for_update(m, default_bandwidth) for m in existing_members]
        if not any(str(m.get("id")) == str(gwid) for m in members):
            # 新成员带宽: 优先沿用现有成员带宽, 否则用 default_bandwidth
            new_bw = default_bandwidth
            for em in existing_members:
                if em.get("bandwidth") is not None:
                    new_bw = em.get("bandwidth")
                    break
            members.append(self._member_for_update({"id": gwid, "bandwidth": new_bw}, default_bandwidth))
        return self.update_sdwan_group(sdwan_id, group_id, members, token=token, **kw)

    def remove_sdwan_member(self, sdwan_id, group_id, gwid, existing_members,
                            default_bandwidth=10, token: str = None, **kw) -> dict:
        """把 gwid 移出分组(基于现有成员 GET-then-update)。"""
        members = [self._member_for_update(m, default_bandwidth)
                   for m in existing_members if str(m.get("id")) != str(gwid)]
        return self.update_sdwan_group(sdwan_id, group_id, members, token=token, **kw)

    def member_in_group(self, sdwan_id, gwid, token: str = None) -> dict:
        """查询 gwid 是否在网络的默认分组中。返回 {ok, in_group, members_count}。"""
        g = self.get_default_group(sdwan_id, token=token)
        if not g.get("ok"):
            return {"ok": False, "message": g.get("message")}
        ids = [str(m.get("id")) for m in g.get("members") or []]
        return {"ok": True, "in_group": str(gwid) in ids,
                "members_count": len(ids), "group_id": g.get("group_id"),
                "members": g.get("members")}


__all__ = ["IccCloudHelper"]
