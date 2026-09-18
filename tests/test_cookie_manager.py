import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools import cookie_manager  # noqa: E402
from app.tools.cookie_manager import CookieHub, looks_expired, site_key  # noqa: E402


class CookieManagerTest(unittest.TestCase):
    def test_site_key_ignores_path(self):
        self.assertEqual(site_key("https://example.edu.cn/druid"), "example.edu.cn")
        self.assertEqual(site_key("https://example.edu.cn/actuator"), "example.edu.cn")

    def test_same_host_workers_share_and_relogin(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cookie_manager.worker_config, "work_root", tmp):
                mgr = cookie_manager.CookieManager()
                cookie_manager._MANAGER = mgr
                try:
                    a = CookieHub("task-1", "https://example.edu.cn/druid")
                    b = CookieHub("task-1", "https://example.edu.cn/nacos")
                    a.remember_from_auth_context({
                        "username": "u1", "password": "p1", "login_url": "/signin",
                    })
                    self.assertEqual(b.creds()["username"], "u1")

                    ex = Mock()
                    ex._session_cookies = {"SESSION": "abc"}
                    ex._cookie_jar = [{"name": "SESSION", "value": "abc", "domain": "example.edu.cn", "path": "/"}]
                    ex._session_headers = {}
                    a.ingest(ex, status="login_ok")
                    self.assertTrue(b.has_session())

                    other = CookieHub("task-2", "https://example.edu.cn/druid")
                    self.assertFalse(other.has_session())
                finally:
                    cookie_manager._MANAGER = cookie_manager.CookieManager()

    def test_ingest_merges_sibling_cookies(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cookie_manager.worker_config, "work_root", tmp):
                mgr = cookie_manager.CookieManager()
                cookie_manager._MANAGER = mgr
                try:
                    a = CookieHub("task-1", "https://example.edu.cn/druid")
                    b = CookieHub("task-1", "https://example.edu.cn/actuator")
                    ex_a = Mock()
                    ex_a._session_cookies = {"A": "1"}
                    ex_a._cookie_jar = [{"name": "A", "value": "1", "domain": "example.edu.cn", "path": "/"}]
                    ex_a._session_headers = {}
                    a.ingest(ex_a)
                    ex_b = Mock()
                    ex_b._session_cookies = {"B": "2"}
                    ex_b._cookie_jar = [{"name": "B", "value": "2", "domain": "example.edu.cn", "path": "/"}]
                    ex_b._session_headers = {}
                    b.ingest(ex_b)
                    names = {e["name"] for e in mgr.slot("task-1", "example.edu.cn").cookie_jar}
                    self.assertEqual(names, {"A", "B"})
                    self.assertEqual(mgr.slot("task-1", "example.edu.cn").cookies["A"], "1")
                    self.assertEqual(mgr.slot("task-1", "example.edu.cn").cookies["B"], "2")
                finally:
                    cookie_manager._MANAGER = cookie_manager.CookieManager()

    def test_remember_user_cookies_for_siblings(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cookie_manager.worker_config, "work_root", tmp):
                mgr = cookie_manager.CookieManager()
                cookie_manager._MANAGER = mgr
                try:
                    a = CookieHub("task-1", "https://example.edu.cn/.env")
                    b = CookieHub("task-1", "https://example.edu.cn/nacos")
                    a.remember_from_auth_context({"cookies": {"CASTGC": "ticket"}})
                    self.assertTrue(b.has_session())
                    self.assertEqual(b.creds(), {})
                finally:
                    cookie_manager._MANAGER = cookie_manager.CookieManager()

    def test_looks_expired_login_wall_200(self):
        self.assertTrue(looks_expired(
            {"ok": True, "status_code": 200, "url": "https://example.edu.cn/druid", "body": "请登录后访问"},
            True,
        ))
        self.assertFalse(looks_expired(
            {"ok": True, "status_code": 200, "url": "https://example.edu.cn/", "body": "欢迎回来"},
            True,
        ))


class OpenSourceNoLeakSearchTest(unittest.TestCase):
    def test_auth_bootstrap_has_no_leaked_cred_search(self):
        from app.agents import auth_bootstrap
        self.assertFalse(hasattr(auth_bootstrap, "bootstrap_leaked_creds"))
        self.assertFalse(hasattr(auth_bootstrap, "leaked_creds_to_try"))
        self.assertTrue(callable(getattr(auth_bootstrap, "has_login_material")))

    def test_leakcreds_stub_returns_empty(self):
        from app.tools.leakcreds import query_leaked_creds
        out = query_leaked_creds("example.edu.cn")
        self.assertEqual(out.get("creds"), [])
        self.assertFalse(out.get("ok"))

    def test_collector_does_not_import_leak_search(self):
        src = (Path(__file__).resolve().parents[1] / "app/agents/collector.py").read_text(encoding="utf-8")
        self.assertNotIn("query_leaked_creds", src)
        self.assertNotIn("_enrich_leaked_creds", src)
        self.assertNotIn("stealer", src.lower())


if __name__ == "__main__":
    unittest.main()
