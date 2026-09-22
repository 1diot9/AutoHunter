"""用户 cookie 必须整组注入，并跟随跳转绑到业务主机。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents.auth_bootstrap import bootstrap_auth, overlay_auth_context  # noqa: E402
from app.tools import cookie_manager  # noqa: E402
from app.tools.cookie_manager import CookieHub  # noqa: E402
from app.tools.executor import ToolExecutor  # noqa: E402


COOKIE = (
    "JSESSIONID=js; serviceToken=abc+def/ghi=; cUserId=user; "
    "wbillcenter_slh=slh+x=; wbillcenter_ph=ph=="
)
NAMES = ["JSESSIONID", "serviceToken", "cUserId", "wbillcenter_slh", "wbillcenter_ph"]


class OverlayTest(unittest.TestCase):
    def test_every_cookie_field_is_kept(self):
        ctx = overlay_auth_context(
            {"cookies": {"JSESSIONID": "stale"}, "matched": True},
            {"type": "cookie", "cookie": COOKIE},
        )
        self.assertEqual(list(ctx["cookies"]), NAMES)
        self.assertEqual(ctx["cookies"]["serviceToken"], "abc+def/ghi=")
        self.assertEqual(ctx["cookies"]["JSESSIONID"], "js")
        self.assertIn("cookie", ctx["kinds"])

    def test_password_submission_does_not_wipe_context(self):
        ctx = {"cookies": {"A": "1"}, "kinds": ["cookie"], "matched": True}
        out = overlay_auth_context(ctx, {"type": "password", "username": "u", "password": "p"})
        self.assertEqual(out["cookies"], {"A": "1"})


class _FakeExecutor:
    def __init__(self):
        self.cookies = {}
        self.spread_names = []

    def session_set(self, cookies=None, headers=None, clear=False):
        self.cookies = dict(cookies or {})
        return {"ok": True}

    def spread_cookies_to_redirect_hosts(self, names):
        self.spread_names = list(names)
        return ["mibi.xiaomi.com", "mibi.wali.com"]


class BootstrapInjectTest(unittest.TestCase):
    def test_bootstrap_spreads_every_field(self):
        ex = _FakeExecutor()
        ctx = overlay_auth_context(None, {"type": "cookie", "cookie": COOKIE})
        result = bootstrap_auth(ex, ctx, "https://mibi.xiaomi.com")
        self.assertEqual(result.status, "injected")
        self.assertEqual(set(ex.cookies), set(NAMES))
        self.assertEqual(ex.spread_names, NAMES)
        self.assertEqual(set(result.cookie_names), set(NAMES))
        self.assertIn("mibi.wali.com", result.reason)


class RedirectDomainTest(unittest.TestCase):
    def test_redirect_host_receives_every_cookie(self):
        seen = []

        def fetch(url, cookies):
            seen.append((url, set(cookies)))
            if url == "https://mibi.xiaomi.com":
                return 301, "https://mibi.wali.com/"
            if url == "https://mibi.wali.com/":
                return 200, ""
            raise AssertionError(url)

        with tempfile.TemporaryDirectory() as tmp:
            ex = ToolExecutor("https://mibi.xiaomi.com", work_dir=tmp)
            ex._redirect_hop = fetch
            ex.session_set(cookies={
                "JSESSIONID": "js",
                "serviceToken": "abc+def/ghi=",
                "cUserId": "user",
                "wbillcenter_slh": "slh+x=",
                "wbillcenter_ph": "ph==",
            })
            hosts = ex.spread_cookies_to_redirect_hosts(NAMES)
            self.assertEqual(hosts, ["mibi.xiaomi.com", "mibi.wali.com"])
            for host in hosts:
                got = ex._cookies_for_host(host)
                self.assertEqual(set(got), set(NAMES))
                self.assertEqual(got["serviceToken"], "abc+def/ghi=")
            self.assertEqual(seen[0][1], set(NAMES))
            self.assertEqual(seen[1][0], "https://mibi.wali.com/")
            headers, _applied = ex._apply_session({}, "https://mibi.wali.com/recharge/charge")
            sent = headers["Cookie"]
            for name in NAMES:
                self.assertIn(name + "=", sent)
            self.assertIn("abc+def/ghi=", sent)

            ex.session_set(cookies={"extra": "1"})
            self.assertEqual(ex._cookies_for_host("mibi.wali.com")["extra"], "1")
            self.assertEqual(ex._cookies_for_host("mibi.xiaomi.com")["extra"], "1")

    def test_location_adopts_pinned_cookies(self):
        with tempfile.TemporaryDirectory() as tmp:
            ex = ToolExecutor("https://mibi.xiaomi.com", work_dir=tmp)
            ex.session_set(cookies={"serviceToken": "abc+def/ghi=", "wbillcenter_slh": "slh"})
            pinned = ex._pinned_user_cookies("mibi.xiaomi.com")

            class Resp:
                headers = {"location": "https://mibi.wali.com/"}
                history = []
                url = "https://mibi.xiaomi.com/"

            ex._bind_pinned_locations(pinned, Resp())
            got = ex._cookies_for_host("mibi.wali.com")
            self.assertEqual(got["serviceToken"], "abc+def/ghi=")
            self.assertEqual(got["wbillcenter_slh"], "slh")


class AliasPersistTest(unittest.TestCase):
    def test_alias_hosts_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cookie_manager.worker_config, "work_root", tmp):
                mgr = cookie_manager.CookieManager()
                cookie_manager._MANAGER = mgr
                try:
                    hub = CookieHub("task-1", "https://mibi.xiaomi.com")

                    class Ex:
                        def __init__(self):
                            self._cookie_alias_hosts = ["mibi.xiaomi.com", "mibi.wali.com"]
                            self._session_cookies = {"serviceToken": "abc+def/ghi="}
                            self._cookie_jar = [{
                                "name": "serviceToken",
                                "value": "abc+def/ghi=",
                                "domain": "mibi.wali.com",
                                "path": "/",
                            }]
                            self._session_headers = {}

                        def restore_resume_state(self, **kwargs):
                            self.restored = kwargs
                            self._session_cookies = {"serviceToken": "abc+def/ghi="}

                    src = Ex()
                    hub.ingest(src, status="injected")
                    dst = Ex()
                    dst._cookie_alias_hosts = []
                    self.assertTrue(hub.apply(dst))
                    self.assertEqual(dst._cookie_alias_hosts, ["mibi.xiaomi.com", "mibi.wali.com"])
                finally:
                    cookie_manager._MANAGER = cookie_manager.CookieManager()


if __name__ == "__main__":
    unittest.main()
