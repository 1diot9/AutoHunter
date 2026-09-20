"""Proxy-mode Set-Cookie absorption must use _put_cookie_entry."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.executor import ToolExecutor, _split_set_cookie  # noqa: E402


class ProxyCookieAbsorbTest(unittest.TestCase):
    def test_split_set_cookie(self):
        parsed = _split_set_cookie("CASTGC=ticket; Path=/cas; Domain=.tongji.edu.cn; HttpOnly")
        self.assertEqual(parsed, ("CASTGC", "ticket", ".tongji.edu.cn", "/cas"))

    def test_parse_proxy_headers_uses_put_cookie_entry(self):
        self.assertFalse(hasattr(ToolExecutor, "_put_cookie"))
        with tempfile.TemporaryDirectory() as tmp:
            ex = ToolExecutor("https://math.tongji.edu.cn/", work_dir=tmp)
            raw = (
                "HTTP/1.1 302 Found\r\n"
                "Set-Cookie: CASTGC=ticket; Path=/cas; Domain=.tongji.edu.cn; HttpOnly\r\n"
                "Location: https://math.tongji.edu.cn/\r\n"
                "\r\n"
                "HTTP/1.1 200 OK\r\n"
                "Set-Cookie: JSESSIONID=abc; Path=/\r\n"
                "Content-Type: text/html\r\n"
                "\r\n"
            )
            headers, chain, updated = ex._parse_proxy_headers(
                raw, url="https://math.tongji.edu.cn/login"
            )
            self.assertEqual(chain, ["302", "200"])
            self.assertEqual(headers.get("Content-Type"), "text/html")
            self.assertIn("CASTGC", updated)
            self.assertIn("JSESSIONID", updated)
            by_name = {e["name"]: e for e in ex._cookie_jar}
            self.assertEqual(by_name["CASTGC"]["domain"], "tongji.edu.cn")
            self.assertEqual(by_name["CASTGC"]["path"], "/cas")
            self.assertEqual(by_name["JSESSIONID"]["domain"], "math.tongji.edu.cn")
            self.assertEqual(by_name["JSESSIONID"]["value"], "abc")
            cookies = ex._cookies_for_host("math.tongji.edu.cn")
            self.assertEqual(cookies["CASTGC"], "ticket")
            self.assertEqual(cookies["JSESSIONID"], "abc")


if __name__ == "__main__":
    unittest.main()
