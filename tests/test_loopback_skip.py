"""Issue #49：域名/IP 指向回环时必须跳过，不能打到 AutoHunter 自己。"""
from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from app.agents.prefilter import LOOPBACK_SKIP_REASON, should_skip, should_skip_ex
from app.tools.guard import CommandBlocked, check_command, check_http_request
from app.tools.netguard import command_hits_loopback, is_loopback_ip, is_loopback_target


class LoopbackSkipTests(unittest.TestCase):
    def test_literal_loopback(self):
        for h in (
            "127.0.0.1",
            "127.0.0.2",
            "localhost",
            "localhost.localdomain",
            "::1",
            "[::1]",
            "http://127.0.0.1:18800/",
            "https://localhost:8080/admin",
            "0.0.0.0",
            "::ffff:127.0.0.1",
        ):
            self.assertTrue(is_loopback_target(h), h)

    def test_private_and_public_allowed(self):
        for h in ("10.0.0.1", "192.168.1.8", "8.8.8.8", "example.com"):
            self.assertFalse(is_loopback_target(h), h)

    def test_loopback_ip_helper(self):
        self.assertTrue(is_loopback_ip("127.0.0.1"))
        self.assertTrue(is_loopback_ip("::1"))
        self.assertFalse(is_loopback_ip("10.1.2.3"))
        self.assertFalse(is_loopback_ip("example.com"))

    def test_dns_to_loopback(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        with patch("app.tools.netguard.socket.getaddrinfo", return_value=fake):
            self.assertTrue(is_loopback_target("evil.example"))

    def test_should_skip_no_probe(self):
        with patch("app.agents.prefilter.probe") as probe:
            skip, reason, info = should_skip_ex("127.0.0.1", "http://127.0.0.1/")
            self.assertTrue(skip)
            self.assertIn("回环", reason)
            self.assertEqual(reason, LOOPBACK_SKIP_REASON)
            self.assertEqual(info, {})
            probe.assert_not_called()
        skip, reason = should_skip("localhost", "http://localhost/")
        self.assertTrue(skip)
        self.assertIn("回环", reason)

    def test_should_skip_dns_no_probe(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        with patch("app.tools.netguard.socket.getaddrinfo", return_value=fake):
            with patch("app.agents.prefilter.probe") as probe:
                skip, reason, info = should_skip_ex("evil.example", "http://evil.example/")
                self.assertTrue(skip)
                self.assertIn("回环", reason)
                self.assertEqual(info, {})
                probe.assert_not_called()

    def test_http_request_blocked(self):
        with self.assertRaises(CommandBlocked):
            check_http_request("GET", "http://127.0.0.1:18800/health")

    def test_command_curl_loopback(self):
        self.assertTrue(command_hits_loopback("curl http://127.0.0.1:18800/"))
        self.assertTrue(command_hits_loopback("curl -s http://localhost/admin"))
        self.assertFalse(command_hits_loopback("curl https://example.com/"))
        with self.assertRaises(CommandBlocked):
            check_command("curl http://127.0.0.1:18800/")


if __name__ == "__main__":
    unittest.main()
