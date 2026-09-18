"""Issue #53：ip138 归属查询 + 报告归属证明。不打真实网络。"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from app.tools.edu_ip import (
    _lookup_ip,
    cache_clear,
    lookup_school,
    parse_ip138_html,
    peek_cached,
    school_name_no_dns,
)

_EDU_HTML = """
<div class="table-box">
<table>
<tbody>
<tr class="active"><td class="th">ASN归属地</td><td><span>中国 四川省 成都市</span></td></tr>
<tr><td class="th">运营商</td><td>教育网</td></tr>
<tr><td class="th">标记</td><td>四川大学</td></tr>
<tr><td class="th">IDC服务商</td><td>'+html.join('<br>')+'</td></tr>
</tbody>
</table>
</div>
"""

_IDC_HTML = """
<div class="table-box">
<table>
<tbody>
<tr class="active"><td class="th">ASN归属地</td><td><span>中国 台湾省 台北市</span></td></tr>
<tr><td class="th">iP类型</td><td>数据中心</td></tr>
</tbody>
</table>
</div>
"""


class Ip138LookupTests(unittest.TestCase):
    def setUp(self):
        cache_clear()

    def test_parse_edu_tag(self):
        raw = parse_ip138_html(_EDU_HTML)
        self.assertEqual(raw["tag"], "四川大学")
        self.assertEqual(raw["isp"], "教育网")
        self.assertEqual(raw["location"], "中国 四川省 成都市")
        self.assertNotIn("html.join", raw.get("ip_type", ""))

    def test_parse_skips_js_junk(self):
        raw = parse_ip138_html(_EDU_HTML)
        self.assertNotIn("IDC服务商", raw.values())

    def test_lookup_builds_proof(self):
        with patch("app.tools.edu_ip._fetch_ip138", return_value=parse_ip138_html(_EDU_HTML)):
            info = lookup_school("https://202.115.32.1/login")
        self.assertIsNotNone(info)
        self.assertEqual(info["school"], "四川大学")
        self.assertIn("四川大学", info["proof"])
        self.assertIn("教育网", info["proof"])
        self.assertIn("202.115.32.1", info["proof"])
        self.assertEqual(info["source"], "ip138")

    def test_idc_has_proof_but_no_school(self):
        with patch("app.tools.edu_ip._fetch_ip138", return_value=parse_ip138_html(_IDC_HTML)):
            info = _lookup_ip("141.11.86.91")
        self.assertIsNotNone(info)
        self.assertIsNone(info["school"])
        self.assertIn("数据中心", info["proof"])
        self.assertIn("台北市", info["proof"])

    def test_peek_and_list_path_no_network(self):
        self.assertIsNone(school_name_no_dns("202.115.32.1"))
        with patch("app.tools.edu_ip._fetch_ip138", return_value=parse_ip138_html(_EDU_HTML)) as fetch:
            _lookup_ip("202.115.32.1")
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(school_name_no_dns("202.115.32.1"), "四川大学")
            self.assertIn("四川大学", peek_cached("202.115.32.1")["proof"])
            school_name_no_dns("202.115.32.1")
            self.assertEqual(fetch.call_count, 1)

    def test_domain_list_path_no_dns(self):
        self.assertIsNone(school_name_no_dns("https://www.scu.edu.cn/"))
        self.assertIsNone(peek_cached("https://www.scu.edu.cn/"))

    def test_ipv6_no_crash(self):
        self.assertIsNone(_lookup_ip("2001:db8::1"))

    def test_fetch_fail_not_cached(self):
        with patch("app.tools.edu_ip._fetch_ip138", return_value=None):
            self.assertIsNone(_lookup_ip("1.2.3.4"))
        self.assertIsNone(peek_cached("1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
