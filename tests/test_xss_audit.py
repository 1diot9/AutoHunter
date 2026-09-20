"""XSS 独立审核标准：分类启发式 + reviewer 闸门。"""
from __future__ import annotations

import unittest

from app.agents.reviewer import _ignored_deepen_directive, _maybe_apply_xss_policy, _maybe_deepen_ignored
from app.agents.xss_audit import (
    XssClass,
    classify_xss,
    edu_reflected_xss_block_reason,
    looks_like_xss,
    map_xss_verdict,
    xss_missing_evidence_reason,
)
from app.schemas import Finding, Review, ReviewVerdict, Severity


def _finding(**kwargs) -> Finding:
    base = {
        "vuln_type": "xss",
        "title": "测试站点 - 模块 - XSS",
        "severity_claimed": "中危",
        "target_url": "https://www.example.edu.cn/upload",
        "owner": "测试大学",
        "description": "存在跨站脚本。",
        "steps": ["上传文件", "访问落地 URL"],
        "poc": "curl https://www.example.edu.cn/upload/evil.html",
        "raw_request": "GET /upload/evil.html HTTP/1.1\nHost: www.example.edu.cn",
        "raw_response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<script>alert(1)</script>",
        "evidence": {"notes": "可执行"},
        "affected_scope": "访客",
        "kill_chain": [{"method": "上传", "detail": "HTML"}],
        "self_check": {
            "is_reflected_xss": False,
            "needs_admin_login": False,
            "needs_mitm": False,
            "is_pure_info_leak": False,
            "scanner_only_no_poc": False,
            "is_public_interface": False,
            "info_leak_hits_strict_list": False,
        },
    }
    base.update(kwargs)
    return Finding(**base)


def _review(**kwargs) -> Review:
    base = {
        "verdict": "ignored",
        "confidence": "likely",
        "score": 3.0,
        "in_scope": True,
        "is_duplicate": False,
        "severity_final": None,
        "ignore_reasons": ["疑似低危"],
        "reviewer_notes": "LLM 初判。",
    }
    base.update(kwargs)
    return Review(**base)


class LooksLikeXssTest(unittest.TestCase):
    def test_vuln_type_xss(self):
        self.assertTrue(looks_like_xss(_finding()))

    def test_non_xss(self):
        f = _finding(vuln_type="sql_injection", title="注入", description="SQL", poc="id=1'", raw_response="error")
        self.assertFalse(looks_like_xss(f))


class ClassifySameOriginValidTest(unittest.TestCase):
    def test_same_origin_html_upload_is_valid(self):
        f = _finding(
            target_url="https://www.example.edu.cn/app",
            description="未授权上传 HTML 到目标站，任意访客可访问。",
            poc="访问 https://www.example.edu.cn/uploads/evil.html",
            raw_response=(
                "HTTP/1.1 200 OK\n"
                "Content-Type: text/html; charset=utf-8\n\n"
                "<html><script>document.domain</script></html>"
            ),
            self_check={
                "is_reflected_xss": False,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {
                    "subtype": "upload",
                    "js_executes": True,
                    "execution_url": "https://www.example.edu.cn/uploads/evil.html",
                    "execution_origin": "https://www.example.edu.cn",
                    "same_origin_as_target": True,
                    "reachable_by_others": True,
                    "content_type": "text/html",
                    "content_disposition": "",
                    "cross_origin_trust": "unknown",
                },
            },
        )
        cls = classify_xss(f)
        self.assertEqual(cls.classification, XssClass.VALID_XSS)
        self.assertEqual(cls.confidence, "high")

    def test_llm_ignored_uplifted_to_accepted(self):
        f = _finding(
            target_url="https://portal.example.edu.cn/",
            poc="https://portal.example.edu.cn/static/x.html",
            raw_response="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<script>1</script>",
            self_check={
                "is_reflected_xss": False,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {
                    "subtype": "stored",
                    "execution_url": "https://portal.example.edu.cn/static/x.html",
                    "execution_origin": "https://portal.example.edu.cn",
                    "same_origin_as_target": True,
                    "content_type": "text/html",
                    "reachable_by_others": True,
                },
            },
        )
        review = _review(verdict="ignored")
        self.assertTrue(_maybe_apply_xss_policy(f, review, "edusrc"))
        self.assertEqual(review.verdict, ReviewVerdict.accepted)
        self.assertEqual(review.severity_final, Severity.medium)
        self.assertIn("VALID_XSS", review.reviewer_notes)


class EduReflectedHardIgnoreTest(unittest.TestCase):
    def test_edu_reflected_forced_ignored_and_no_deepen(self):
        f = _finding(
            title="反射型XSS：搜索参数",
            description="反射型 XSS，参数 q 回显脚本。",
            target_url="https://www.example.edu.cn/search?q=1",
            raw_response="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<script>alert(1)</script>",
            self_check={
                "is_reflected_xss": True,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {
                    "subtype": "reflected",
                    "js_executes": True,
                    "execution_origin": "https://www.example.edu.cn",
                    "same_origin_as_target": True,
                    "content_type": "text/html",
                    "reachable_by_others": True,
                },
            },
        )
        self.assertTrue(edu_reflected_xss_block_reason(f))
        review = _review(verdict="accepted", severity_final="中危", score=5.0)
        self.assertTrue(_maybe_apply_xss_policy(f, review, "edusrc"))
        self.assertEqual(review.verdict, ReviewVerdict.ignored)
        self.assertIn("EduSRC不收反射型XSS", review.ignore_reasons)
        self.assertTrue(getattr(review, "_xss_block_deepen", False))
        # deepen 救回不得生效
        self.assertFalse(_maybe_deepen_ignored(f, review, "edusrc"))
        self.assertEqual(_ignored_deepen_directive(f, review, "edusrc"), "")

    def test_enterprise_reflected_not_hard_ignored(self):
        f = _finding(
            title="反射型XSS：搜索",
            description="反射型 XSS 可诱导其他用户访问。",
            target_url="https://app.corp.com/search?q=1",
            raw_response="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<script>alert(1)</script>",
            self_check={
                "is_reflected_xss": True,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {
                    "subtype": "reflected",
                    "execution_origin": "https://app.corp.com",
                    "same_origin_as_target": True,
                    "content_type": "text/html",
                    "reachable_by_others": True,
                },
            },
        )
        self.assertTrue(edu_reflected_xss_block_reason(f))  # 函数本身只认反射；worker 仅在 Edu 调用
        # 企业 map：反射不强制 ignored（Edu 硬忽略理由）
        cls = classify_xss(f)
        override = map_xss_verdict(cls, "enterprise", f)
        if override is not None:
            self.assertNotEqual(override.ignore_reason, "EduSRC不收反射型XSS")
            self.assertFalse(
                override.block_deepen_rescue and override.ignore_reason == "EduSRC不收反射型XSS"
            )
        # 企业 reviewer 闸门不得因 Edu 规则硬 ignored
        review = _review(verdict="accepted", severity_final="中危", score=5.0)
        _maybe_apply_xss_policy(f, review, "enterprise")
        self.assertNotIn("EduSRC不收反射型XSS", review.ignore_reasons or [])


class BucketOriginTest(unittest.TestCase):
    def test_bucket_no_trust_stated_out_of_scope(self):
        f = _finding(
            target_url="https://www.example.edu.cn/upload",
            description="上传到七牛，无CORS、无cookie共享，第三方存储无信任关系。",
            poc="https://bucket.qiniucdn.com/evil.html",
            raw_response=(
                "HTTP/1.1 200 OK\n"
                "Content-Type: text/html\n\n"
                "<script>alert(1)</script>"
            ),
            self_check={
                "is_reflected_xss": False,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {
                    "subtype": "third_party_storage",
                    "execution_url": "https://bucket.qiniucdn.com/evil.html",
                    "execution_origin": "https://bucket.qiniucdn.com",
                    "same_origin_as_target": False,
                    "content_type": "text/html",
                    "cross_origin_trust": "none",
                    "reachable_by_others": True,
                },
            },
        )
        cls = classify_xss(f)
        self.assertEqual(cls.classification, XssClass.OUT_OF_SCOPE_ORIGIN)
        review = _review(verdict="accepted", severity_final="中危", score=5.0)
        self.assertTrue(_maybe_apply_xss_policy(f, review, "edusrc"))
        self.assertEqual(review.verdict, ReviewVerdict.ignored)

    def test_bucket_no_cross_origin_mention_insufficient(self):
        f = _finding(
            target_url="https://www.example.edu.cn/",
            description="上传 HTML 到对象存储桶，可访问。",
            poc="https://mybucket.oss-cn-hangzhou.aliyuncs.com/a.html",
            raw_response="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<script>1</script>",
            self_check={
                "is_reflected_xss": False,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {
                    "subtype": "third_party_storage",
                    "execution_url": "https://mybucket.oss-cn-hangzhou.aliyuncs.com/a.html",
                    "execution_origin": "https://mybucket.oss-cn-hangzhou.aliyuncs.com",
                    "same_origin_as_target": False,
                    "content_type": "text/html",
                    "cross_origin_trust": "unknown",
                },
            },
        )
        cls = classify_xss(f)
        self.assertEqual(cls.classification, XssClass.INSUFFICIENT_EVIDENCE)
        review = _review(verdict="accepted", severity_final="高危", score=7.0)
        self.assertTrue(_maybe_apply_xss_policy(f, review, "edusrc"))
        self.assertEqual(review.verdict, ReviewVerdict.deepen)
        self.assertIn("Cookie", review.deepen_directive)
        self.assertIn("CORS", review.deepen_directive)


class NonExecutableUploadTest(unittest.TestCase):
    def test_attachment_not_accepted(self):
        f = _finding(
            description="上传 HTML 文件，服务器强制下载。",
            poc="https://www.example.edu.cn/files/evil.html",
            raw_response=(
                "HTTP/1.1 200 OK\n"
                "Content-Type: application/octet-stream\n"
                "Content-Disposition: attachment; filename=evil.html\n\n"
                "<script>alert(1)</script>"
            ),
            self_check={
                "is_reflected_xss": False,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {
                    "subtype": "upload",
                    "execution_url": "https://www.example.edu.cn/files/evil.html",
                    "execution_origin": "https://www.example.edu.cn",
                    "same_origin_as_target": True,
                    "content_type": "application/octet-stream",
                    "content_disposition": "attachment; filename=evil.html",
                },
            },
        )
        cls = classify_xss(f)
        self.assertEqual(cls.classification, XssClass.NON_EXECUTABLE_UPLOAD)
        review = _review(verdict="accepted", severity_final="中危", score=5.0)
        self.assertTrue(_maybe_apply_xss_policy(f, review, "edusrc"))
        self.assertNotEqual(review.verdict, ReviewVerdict.accepted)


class SelfAndHtmlInjectionTest(unittest.TestCase):
    def test_self_xss_ignored(self):
        f = _finding(
            title="Self-XSS",
            description="Self-XSS：只有攻击者自己打开自己构造的页面才能执行。",
            self_check={
                "is_reflected_xss": False,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {
                    "subtype": "self",
                    "reachable_by_others": False,
                    "js_executes": True,
                    "execution_origin": "https://www.example.edu.cn",
                    "content_type": "text/html",
                },
            },
        )
        self.assertEqual(classify_xss(f).classification, XssClass.SELF_XSS)
        review = _review(verdict="accepted", severity_final="低危")
        self.assertTrue(_maybe_apply_xss_policy(f, review, "edusrc"))
        self.assertEqual(review.verdict, ReviewVerdict.ignored)

    def test_html_injection_only_ignored(self):
        f = _finding(
            title="HTML注入",
            description="仅 HTML 注入，无法执行 JS，不能执行javascript。",
            self_check={
                "is_reflected_xss": False,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {
                    "subtype": "html_injection",
                    "js_executes": False,
                },
            },
        )
        self.assertEqual(classify_xss(f).classification, XssClass.HTML_INJECTION)
        review = _review(verdict="accepted")
        self.assertTrue(_maybe_apply_xss_policy(f, review, "edusrc"))
        self.assertEqual(review.verdict, ReviewVerdict.ignored)


class HttpOnlyNotIgnoreTest(unittest.TestCase):
    def test_httponly_alone_does_not_ignore_valid(self):
        f = _finding(
            description="存储型 XSS，Cookie 为 HttpOnly 无法 document.cookie 读取，但仍可调 API。",
            poc="https://www.example.edu.cn/profile",
            raw_response="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<script>fetch('/api')</script>",
            self_check={
                "is_reflected_xss": False,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {
                    "subtype": "stored",
                    "execution_url": "https://www.example.edu.cn/profile",
                    "execution_origin": "https://www.example.edu.cn",
                    "same_origin_as_target": True,
                    "content_type": "text/html",
                    "reachable_by_others": True,
                },
            },
        )
        cls = classify_xss(f)
        self.assertEqual(cls.classification, XssClass.VALID_XSS)
        review = _review(verdict="ignored", ignore_reasons=["无法读取HttpOnly Cookie"])
        self.assertTrue(_maybe_apply_xss_policy(f, review, "edusrc"))
        self.assertEqual(review.verdict, ReviewVerdict.accepted)


class MissingEvidenceWorkerGateTest(unittest.TestCase):
    def test_upload_without_content_type_blocked(self):
        f = _finding(
            description="未授权上传 HTML 存储型 XSS。",
            poc="上传成功",
            raw_response="HTTP/1.1 200 OK\n\n{\"url\":\"/f.html\"}",
            self_check={
                "is_reflected_xss": False,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
                "xss_check": {"subtype": "upload"},
            },
        )
        reason = xss_missing_evidence_reason(f)
        self.assertTrue(reason)
        self.assertIn("Content-Type", reason)


class EnterpriseNeverDeepenReflectedTest(unittest.TestCase):
    def test_enterprise_allows_deepen_marker_path(self):
        """企业模式下反射型 XSS 不在 never-deepen 硬拦（若其它条件满足可 deepen）。"""
        f = _finding(
            vuln_type="unauthorized_access",
            title="未授权配置接口可继续",
            description="未授权系统配置可枚举，反射型xss字样不应在企业挡住 deepen。",
            self_check={
                "is_reflected_xss": False,
                "needs_admin_login": False,
                "needs_mitm": False,
                "is_pure_info_leak": False,
                "scanner_only_no_poc": False,
            },
        )
        review = _review(
            verdict="ignored",
            in_scope=True,
            ignore_reasons=["半成品"],
            reviewer_notes="未授权配置，下一步可登录验证。",
        )
        # 含「反射型xss」文本时：edu 不 deepen，enterprise 可（若其它信号够）
        review2 = _review(
            verdict="ignored",
            in_scope=True,
            ignore_reasons=["半成品"],
            reviewer_notes="未授权系统配置接口，疑似反射型xss无关；应继续验证默认口令登录。",
        )
        # 只要有未授权+配置信号，enterprise 应给出 directive
        d_ent = _ignored_deepen_directive(f, review, "enterprise")
        self.assertTrue(d_ent)


if __name__ == "__main__":
    unittest.main()
