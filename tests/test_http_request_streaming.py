"""multipart/files 请求体是流式的，dump raw_request 不能读 req.content。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

import httpx

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.executor import ToolExecutor  # noqa: E402


class RawRequestStreamingTest(unittest.TestCase):
    def test_multipart_request_content_is_unread(self):
        req = httpx.Request(
            "POST",
            "https://example.edu.cn/upload",
            files={"file": ("a.txt", b"hello", "text/plain")},
        )
        with self.assertRaises(RuntimeError) as ctx:
            _ = req.content
        self.assertIn("streaming request content", str(ctx.exception))

    def test_raw_request_multipart_does_not_raise(self):
        req = httpx.Request(
            "POST",
            "https://example.edu.cn/upload",
            files={"file": ("a.txt", b"hello", "text/plain")},
        )
        text = ToolExecutor._raw_request(
            req, None, None, {"file": ("a.txt", b"hello", "text/plain")},
        )
        self.assertIn("POST", text)
        self.assertIn("example.edu.cn", text)
        self.assertIn("<multipart: file>", text)

    def test_raw_request_json_still_dumps_body(self):
        req = httpx.Request(
            "POST",
            "https://example.edu.cn/api",
            json={"q": "1"},
        )
        text = ToolExecutor._raw_request(req, None, {"q": "1"})
        self.assertIn('"q":', text)
        self.assertIn("1", text)

    def test_http_request_files_succeeds_without_buffering_body(self):
        class ConsumeStreamTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                # 真实 HTTPTransport 只消耗 stream，不会 request.read() 填 _content。
                for _ in request.stream:
                    pass
                return httpx.Response(200, text="uploaded")

        with tempfile.TemporaryDirectory() as tmp:
            ex = ToolExecutor("https://example.edu.cn/", work_dir=tmp)
            ex._client = httpx.Client(
                transport=ConsumeStreamTransport(),
                verify=False,
            )
            result = ex.http_request(
                "https://example.edu.cn/upload",
                method="POST",
                files={"file": {"filename": "a.txt", "content": "hello"}},
            )
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("status_code"), 200)
        self.assertEqual(result.get("body"), "uploaded")
        self.assertNotIn("streaming request content", str(result))
        self.assertIn("multipart: file", result.get("raw_request", ""))


if __name__ == "__main__":
    unittest.main()
