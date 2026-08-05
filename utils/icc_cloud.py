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

    def get_bind_status(self, gwid: str, token: str = None) -> dict:
        """查询设备云端状态: GET /v4/dm/devices/{gwid} (尝试性查询)。

        ICC 查询端点未由产品文档固定, 此方法尽力查询; 失败不影响解绑主流程
        (解绑是否成功以 unbind 响应 + 设备侧 register 表为准)。
        """
        token = token or self._token
        if not token:
            return {"ok": False, "message": "无 token"}
        url = f"{self.API_BASE}/v4/dm/devices/{gwid}"
        try:
            resp = requests.get(url, headers=self._headers(token),
                                timeout=20, verify=False)
        except Exception as e:
            return {"ok": False, "message": f"请求异常: {str(e)[:120]}"}
        data = {}
        try:
            data = resp.json()
        except Exception:
            pass
        return {"ok": resp.status_code == 200, "status": resp.status_code,
                "code": data.get("code"), "data": data, "raw_text": resp.text[:300]}


__all__ = ["IccCloudHelper"]
