"""XSS 独立审核标准（代码闸门 + 专章提示词）。

不做成浏览器 SOP 引擎。内部分类写入 reviewer_notes / ignore_reasons / deepen_directive，
对外仍映射到 accepted / ignored / deepen。EduSRC 反射型 XSS 平台硬忽略。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

from app.agents.edu_scope import _s, finding_text
from app.agents.prompts import normalize_src_type

# ── 内部分类（不进 DB / API 枚举）──────────────────────────────────────────


class XssClass(str, Enum):
    VALID_XSS = "VALID_XSS"
    LOW_IMPACT_XSS = "LOW_IMPACT_XSS"
    SELF_XSS = "SELF_XSS"
    HTML_INJECTION = "HTML_INJECTION"
    NON_EXECUTABLE_UPLOAD = "NON_EXECUTABLE_UPLOAD"
    OUT_OF_SCOPE_ORIGIN = "OUT_OF_SCOPE_ORIGIN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_XSS = "NOT_XSS"


_XSS_TYPE_MARKERS = (
    "xss", "crosssitescripting", "cross-site-scripting", "跨站脚本",
    "存储型xss", "反射型xss", "domxss", "dom xss", "self-xss", "self xss",
    "html injection", "html注入", "svg xss", "上传xss", "文件上传xss",
)
_XSS_TEXT_MARKERS = (
    "xss", "跨站脚本", "存储型 xss", "反射型 xss", "dom xss", "self-xss",
    "html 注入", "html注入", "svg 注入", "上传 html", "上传html",
    "<script", "onerror=", "onload=", "javascript:",
)
_REFLECTED_MARKERS = (
    "反射型xss", "反射型 xss", "反射xss", "反射 xss",
    "reflected xss", "reflect xss", "反射型跨站",
)
_SELF_MARKERS = (
    "self-xss", "self xss", "selfxss",
    "仅自己访问", "只有攻击者", "只能自己打开", "自己构造的页面",
    "攻击者自己打开", "需攻击者手动", "仅本人触发",
)
_HTML_INJECTION_ONLY = (
    "html注入", "html 注入", "html injection",
    "无法执行js", "无法执行 javascript", "不能执行js", "不能执行javascript",
    "仅注入html", "只是html注入", "无javascript执行",
)
_NO_TRUST_MARKERS = (
    "无cors", "没有cors", "cors不可读", "无法读取响应",
    "无cookie共享", "没有cookie共享", "cookie不共享",
    "无跨域信任", "无同源价值", "无信任关系",
    "第三方存储", "第三方cdn", "无关第三方",
)
_TRUST_PROOF_MARKERS = (
    "cors允许", "access-control-allow-origin", "access-control-allow-credentials",
    "cookie domain=", "domain=.example", "postmessage",
    "oauth", "sso 信任", "可读主站", "带凭证跨域",
)
_EXECUTABLE_CT = (
    "text/html", "application/xhtml", "image/svg", "text/xml",
    "application/xml", "application/xhtml+xml",
)
_NON_EXEC_CT = (
    "application/octet-stream", "application/force-download",
    "binary/octet-stream",
)
_STORAGE_HOST_RE = re.compile(
    r"(?:"
    r"\.s3[.\-].*amazonaws\.com|"
    r"\.oss[-.].*aliyuncs\.com|"
    r"\.cos\..*myqcloud\.com|"
    r"\.qiniucdn\.com|\.qiniudn\.com|\.clouddn\.com|"
    r"\.upyun\.com|\.upaiyun\.com|"
    r"\.minio\.|"
    r"storage\.googleapis\.com|"
    r"blob\.core\.windows\.net|"
    r"objects?\..*\.digitaloceanspaces\.com"
    r")$",
    re.I,
)
_CT_RE = re.compile(r"(?im)^content-type:\s*([^\r\n;]+)")
_CD_RE = re.compile(r"(?im)^content-disposition:\s*([^\r\n]+)")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)

EDU_REFLECTED_BLOCK_REASON = (
    "EduSRC 不收反射型 XSS。即使 JavaScript 能在目标 Origin 执行，平台规则仍直接 ignored，不要提交。"
)

XSS_MISSING_EVIDENCE_GUIDANCE = (
    "XSS 类 Finding 证据不足，先补齐再交："
    "① 最终访问 URL（浏览器打开后执行 JS 的那个 URL）；"
    "② 访问该 URL 的完整响应头，尤其 Content-Type / Content-Disposition；"
    "③ execution_origin（scheme://host:port）以及是否与目标站同源；"
    "④ 他人是否能在正常业务中访问到该内容（公开 URL / 评论 / 资料页等）。"
    "禁止假设 Cookie 共享、CORS 可读写或他人会访问。"
)

# ── 专章提示词 ─────────────────────────────────────────────────────────────

_XSS_CORE = """# XSS 独立审核标准（7 步，必须按序）
不要因为出现 <script>、HTML/SVG 注入、事件处理器、alert(document.domain)、能上传 HTML、同公司/同主域、没有 HttpOnly，就直接认定为高危 XSS。必须分析执行上下文与实际影响。

1. Execution：JavaScript 是否真能执行？仅 HTML 注入无法执行 JS → HTML_INJECTION，不是 XSS。上传若 Content-Disposition: attachment 或 Content-Type: application/octet-stream → NON_EXECUTABLE_UPLOAD。
2. Origin：记录最终页面 URL、Scheme、Host、Port、Origin。严格按浏览器 Same-Origin Policy；同公司/同主域 ≠ 同源。对象存储/CDN/OSS/S3 上的文件执行 Origin 是桶域名，不是主站。
3. Reachability：能否让其他用户访问？仅攻击者自己打开 → SELF_XSS。Stored（评论/资料/工单/公开上传 URL）优先评估。
4. Privilege：该 Origin 能访问当前用户 Cookie/Storage/CSRF Token/敏感 DOM/API 吗？HttpOnly 不能 document.cookie 读取 ≠ XSS 无害（仍可能以用户身份调 API）。
5. Cross-Origin Relationship：Cookie Domain 共享、CORS（能发请求 ≠ 能读响应）、postMessage、OAuth/SSO、iframe 等——无实证不得假设。
6. Impact：实际能读/改/调什么、影响谁（含管理员）。
7. Classification → 项目裁决：
   - VALID_XSS → accepted（目标 Origin 可执行且他人可达；存储型默认中危；管理员触发可高危；不要求弹窗、不要求能读 Cookie）
   - LOW_IMPACT_XSS / SELF_XSS / HTML_INJECTION / OUT_OF_SCOPE_ORIGIN → ignored
   - NON_EXECUTABLE_UPLOAD → ignored 或 deepen（指令指向 getshell/证明可执行，不当 XSS 收）
   - INSUFFICIENT_EVIDENCE → deepen（列出待验证项，禁止编造 Cookie/CORS/他人访问）
在 reviewer_notes 写明「[XSS判定] <分类>」与依据。
"""

XSS_REVIEW_PROMPT_EDU = _XSS_CORE + """
# EduSRC 硬规则
反射型 XSS（含 self_check.is_reflected_xss=true）→ 强制 ignored，理由「EduSRC不收反射型XSS」，永不 deepen。
Self-XSS → ignored。
目标站自身 Origin 下存储型/上传 HTML/SVG/XML，访问响应 Content-Type 为 text/html（或 svg/xml）且非 attachment、他人可访问 → VALID_XSS，accepted 中危。
第三方存储 Origin 且报告已写明无跨域信任 → OUT_OF_SCOPE_ORIGIN ignored；完全未谈跨域关系 → INSUFFICIENT_EVIDENCE deepen。
"""

XSS_REVIEW_PROMPT_ENTERPRISE = _XSS_CORE + """
# 企业 SRC
反射型 XSS 不硬忽略：若 JS 在目标 Origin 执行且能诱导其他用户访问，可按 VALID_XSS accepted（按实际影响定级）。
Self-XSS / 纯 HTML 注入 / 隔离第三方 Origin 无信任关系 → ignored。
证据不足 → deepen，列出缺的 Origin/Content-Type/可达性/跨域信任实证。
"""

XSS_WORKER_PROMPT = """# XSS 取证与提交（独立标准）
提交 XSS/HTML 注入/上传 XSS 前必须按 7 步想清楚：Execution → Origin → Reachability → Privilege → Cross-Origin → Impact → Classification。
- 先 GET 最终访问 URL，把响应头（Content-Type / Content-Disposition）和执行 Origin 写进 raw_response / self_check.xss_check。
- 同公司/同主域 ≠ 同源。对象存储/CDN 上的 HTML 执行 Origin 是桶域名；无 CORS/Cookie/postMessage 等跨域信任实证时，不要当主站 Stored XSS 交；缺证据用 finish.deepen_lead。
- 目标站自身 Origin + 可执行 Content-Type（text/html 等）+ 非 attachment + 他人可访问（公开上传 URL 即算）→ 可交存储型 XSS；不要求弹窗。
- Self-XSS、仅 HTML 注入无法执行 JS、强制下载头 → 不要交。
- self_check.xss_check 尽量填：subtype、js_executes、execution_url、execution_origin、same_origin_as_target、reachable_by_others、content_type、content_disposition、cross_origin_trust、missing_evidence。
- subtype=reflected 时 is_reflected_xss 必须为 true。
"""

XSS_WORKER_PROMPT_EDU = XSS_WORKER_PROMPT + """
EduSRC：反射型 XSS / Self-XSS 禁止提交（平台硬忽略）。
"""


# ── 数据结构 ───────────────────────────────────────────────────────────────


@dataclass
class XssClassification:
    classification: XssClass
    reason: str
    confidence: str = "heuristic"  # high | heuristic | low
    execution_origin: str = ""
    target_origin: str = ""
    content_type: str = ""
    content_disposition: str = ""
    missing: list[str] = field(default_factory=list)
    is_reflected: bool = False
    is_self: bool = False
    same_origin: Optional[bool] = None
    storage_host: bool = False


@dataclass
class XssVerdictOverride:
    """系统改判意图；None 字段表示不强制覆盖。"""
    force_verdict: Optional[str]  # accepted | ignored | deepen
    classification: XssClass
    reason: str
    severity_final: Optional[str] = None  # 严重/高危/中危/低危
    deepen_directive: str = ""
    ignore_reason: str = ""
    block_deepen_rescue: bool = False


# ── 识别与解析 ─────────────────────────────────────────────────────────────


def looks_like_xss(finding: Any) -> bool:
    vuln = _s(getattr(finding, "vuln_type", "")).lower().replace("_", "").replace("-", "").replace(" ", "")
    if any(m.replace(" ", "").replace("-", "") in vuln for m in _XSS_TYPE_MARKERS):
        return True
    # 上传类但正文在讲 XSS/HTML 执行
    text = finding_text(finding)
    if any(m in text for m in _XSS_TEXT_MARKERS):
        return True
    sc = getattr(finding, "self_check", None)
    if sc is not None and bool(getattr(sc, "is_reflected_xss", False)):
        return True
    xss_check = _xss_check_dict(finding)
    if xss_check.get("subtype") or xss_check.get("execution_url") or xss_check.get("execution_origin"):
        return True
    return False


def _xss_check_dict(finding: Any) -> dict:
    sc = getattr(finding, "self_check", None)
    if sc is None:
        return {}
    xc = getattr(sc, "xss_check", None)
    if xc is None:
        return {}
    if isinstance(xc, dict):
        return xc
    if hasattr(xc, "model_dump"):
        return xc.model_dump(mode="json") or {}
    return {}


def _blob(finding: Any) -> str:
    xc = _xss_check_dict(finding)
    return "\n".join([
        finding_text(finding),
        _s(getattr(finding, "raw_response", "")),
        _s(getattr(finding, "raw_request", "")),
        _s(getattr(finding, "steps", "")),
        _s(xc),
    ]).lower()


def _origin_of(url: str) -> str:
    try:
        p = urlparse(url.strip())
    except Exception:
        return ""
    if not p.scheme or not p.netloc:
        return ""
    host = p.hostname or ""
    if not host:
        return ""
    port = p.port
    if port is None:
        port = 443 if p.scheme == "https" else 80 if p.scheme == "http" else None
    default = (p.scheme == "https" and port == 443) or (p.scheme == "http" and port == 80)
    if default or port is None:
        return f"{p.scheme}://{host}".lower()
    return f"{p.scheme}://{host}:{port}".lower()


def _is_storage_host(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    if not h:
        return False
    if _STORAGE_HOST_RE.search(h):
        return True
    # 常见第三方静态桶关键词（保守，避免误伤业务子域）
    tokens = ("s3.amazonaws", "aliyuncs.com", "myqcloud.com", "qiniucdn", "clouddn", "upyun.com")
    return any(t in h for t in tokens)


def _header_value(raw: str, regex: re.Pattern[str]) -> str:
    m = regex.search(raw or "")
    return (m.group(1).strip() if m else "").lower()


def _pick_execution_url(finding: Any) -> str:
    xc = _xss_check_dict(finding)
    for key in ("execution_url", "executionUrl"):
        v = _s(xc.get(key)).strip()
        if v.startswith("http"):
            return v
    # 描述/PoC/步骤里常见「访问 https://...」
    blob = "\n".join([
        _s(getattr(finding, "description", "")),
        _s(getattr(finding, "poc", "")),
        "\n".join(_s(s) for s in (getattr(finding, "steps", None) or [])),
        _s(getattr(finding, "raw_response", "")),
    ])
    urls = _URL_RE.findall(blob)
    # 优先带 .html/.svg/.xml 的
    for u in urls:
        low = u.lower()
        if any(low.rstrip("/").endswith(ext) for ext in (".html", ".htm", ".svg", ".xml", ".xhtml")):
            return u.rstrip(").,;\"'")
    target = _s(getattr(finding, "target_url", "")).strip()
    if target.startswith("http"):
        return target
    return urls[0].rstrip(").,;\"'") if urls else ""


def _content_type(finding: Any) -> str:
    xc = _xss_check_dict(finding)
    ct = _s(xc.get("content_type") or xc.get("contentType")).lower().strip()
    if ct:
        return ct.split(";")[0].strip()
    return _header_value(_s(getattr(finding, "raw_response", "")), _CT_RE).split(";")[0].strip()


def _content_disposition(finding: Any) -> str:
    xc = _xss_check_dict(finding)
    cd = _s(xc.get("content_disposition") or xc.get("contentDisposition")).lower().strip()
    if cd:
        return cd
    return _header_value(_s(getattr(finding, "raw_response", "")), _CD_RE)


def _is_reflected(finding: Any) -> bool:
    sc = getattr(finding, "self_check", None)
    if sc is not None and bool(getattr(sc, "is_reflected_xss", False)):
        return True
    xc = _xss_check_dict(finding)
    subtype = _s(xc.get("subtype")).lower()
    if subtype == "reflected":
        return True
    text = _blob(finding)
    return any(m in text for m in _REFLECTED_MARKERS)


def _is_self_xss(finding: Any) -> bool:
    xc = _xss_check_dict(finding)
    subtype = _s(xc.get("subtype")).lower()
    if subtype in {"self", "self_xss"}:
        return True
    if xc.get("reachable_by_others") is False:
        return True
    text = _blob(finding)
    return any(m in text for m in _SELF_MARKERS)


def _html_injection_only(finding: Any) -> bool:
    xc = _xss_check_dict(finding)
    subtype = _s(xc.get("subtype")).lower()
    if subtype == "html_injection":
        return True
    if xc.get("js_executes") is False:
        return True
    text = _blob(finding)
    return any(m in text for m in _HTML_INJECTION_ONLY)


def _no_trust_stated(finding: Any) -> bool:
    xc = _xss_check_dict(finding)
    trust = _s(xc.get("cross_origin_trust")).lower()
    if trust == "none":
        return True
    text = _blob(finding)
    return any(m in text for m in _NO_TRUST_MARKERS)


def _trust_proof_stated(finding: Any) -> bool:
    xc = _xss_check_dict(finding)
    trust = _s(xc.get("cross_origin_trust")).lower()
    if trust in {"cookie_share", "cors", "postmessage", "oauth"}:
        return True
    text = _blob(finding)
    return any(m in text for m in _TRUST_PROOF_MARKERS)


def _executable_ct(ct: str) -> bool:
    c = (ct or "").lower()
    return any(c.startswith(x) or x in c for x in _EXECUTABLE_CT)


def _non_executable(ct: str, cd: str) -> bool:
    if "attachment" in (cd or "").lower():
        return True
    c = (ct or "").lower()
    return any(x in c for x in _NON_EXEC_CT)


def classify_xss(finding: Any) -> XssClassification:
    """高置信启发式；缺证据标 INSUFFICIENT_EVIDENCE，不编造。"""
    if not looks_like_xss(finding):
        return XssClassification(XssClass.NOT_XSS, "非 XSS 类 Finding")

    text_blob = _blob(finding)
    is_reflected = _is_reflected(finding)
    is_self = _is_self_xss(finding)
    exec_url = _pick_execution_url(finding)
    xc = _xss_check_dict(finding)
    exec_origin = _s(xc.get("execution_origin") or xc.get("executionOrigin")).strip().lower()
    if not exec_origin and exec_url:
        exec_origin = _origin_of(exec_url)
    target_url = _s(getattr(finding, "target_url", "")).strip()
    target_origin = _origin_of(target_url)
    ct = _content_type(finding)
    cd = _content_disposition(finding)
    storage = False
    if exec_origin:
        try:
            storage = _is_storage_host(urlparse(exec_origin).hostname or "")
        except Exception:
            storage = False
    same: Optional[bool] = None
    if xc.get("same_origin_as_target") is not None:
        same = bool(xc.get("same_origin_as_target"))
    elif exec_origin and target_origin:
        same = exec_origin == target_origin

    missing: list[str] = []
    if not exec_url and not exec_origin:
        missing.append("最终访问 URL / execution_origin")
    if not ct and ("upload" in text_blob or "上传" in text_blob):
        missing.append("Content-Type")

    base_kw = dict(
        execution_origin=exec_origin,
        target_origin=target_origin,
        content_type=ct,
        content_disposition=cd,
        is_reflected=is_reflected,
        is_self=is_self,
        same_origin=same,
        storage_host=storage,
    )

    if is_self:
        return XssClassification(
            XssClass.SELF_XSS,
            "仅攻击者自己可触发 / Self-XSS 信号明确",
            confidence="high",
            **base_kw,
        )

    if _html_injection_only(finding):
        return XssClassification(
            XssClass.HTML_INJECTION,
            "报告标明仅 HTML 注入或 js_executes=false，无法执行 JavaScript",
            confidence="high",
            **base_kw,
        )

    if ct or cd:
        if _non_executable(ct, cd):
            return XssClassification(
                XssClass.NON_EXECUTABLE_UPLOAD,
                "响应为 attachment 或 application/octet-stream，浏览器不会当页面执行 JS",
                confidence="high",
                **base_kw,
            )

    # 第三方存储 Origin
    if storage or (same is False and exec_origin):
        if _trust_proof_stated(finding):
            return XssClassification(
                XssClass.INSUFFICIENT_EVIDENCE,
                "执行 Origin 非目标站，虽声称有跨域信任，但需 reviewer 核实证；代码不自动抬升为 VALID",
                confidence="heuristic",
                missing=["跨域信任实证（CORS 可读响应 / Cookie 共享属性 / postMessage）"],
                **base_kw,
            )
        if _no_trust_stated(finding):
            return XssClassification(
                XssClass.OUT_OF_SCOPE_ORIGIN,
                "执行 Origin 为存储/第三方域，且报告已写明无跨域信任关系",
                confidence="high",
                **base_kw,
            )
        return XssClassification(
            XssClass.INSUFFICIENT_EVIDENCE,
            "执行 Origin 非目标站（或对象存储），未说明跨域信任；禁止假设可偷主站 Cookie",
            confidence="heuristic",
            missing=["跨域信任实证或明确无信任关系说明", "是否影响目标用户/业务"],
            **base_kw,
        )

    # 高置信 VALID：同源 + 可执行 CT + 非 attachment + 非 self
    if same is True and ct and _executable_ct(ct) and not _non_executable(ct, cd) and not is_self:
        return XssClassification(
            XssClass.VALID_XSS,
            "JavaScript 在目标站 Origin 执行，响应可执行 Content-Type 且非强制下载",
            confidence="high",
            **base_kw,
        )

    # 同源但缺 CT：证据不足
    if same is True and not ct:
        return XssClassification(
            XssClass.INSUFFICIENT_EVIDENCE,
            "疑似目标 Origin，但缺少访问响应的 Content-Type 证据",
            confidence="heuristic",
            missing=["访问落地 URL 的 Content-Type / Content-Disposition"],
            **base_kw,
        )

    # 反射但缺执行上下文细节
    if is_reflected and not exec_origin and not ct:
        return XssClassification(
            XssClass.INSUFFICIENT_EVIDENCE,
            "反射型 XSS 声称成立，但缺少最终 Origin / Content-Type 证据",
            confidence="low",
            missing=["反射页面最终 URL 与响应头"],
            is_reflected=True,
            is_self=is_self,
            same_origin=same,
            storage_host=storage,
            execution_origin=exec_origin,
            target_origin=target_origin,
            content_type=ct,
            content_disposition=cd,
        )

    if missing:
        return XssClassification(
            XssClass.INSUFFICIENT_EVIDENCE,
            "XSS 证据链不完整：" + "；".join(missing),
            confidence="heuristic",
            missing=missing,
            **base_kw,
        )

    # 有 XSS 信号但无法高置信归类
    return XssClassification(
        XssClass.INSUFFICIENT_EVIDENCE,
        "存在 XSS 相关信号，但 Origin/可执行性/可达性证据不足以自动定案",
        confidence="low",
        missing=["execution_origin", "Content-Type", "他人可达性说明"],
        **base_kw,
    )


def map_xss_verdict(
    classification: XssClassification,
    src_type: str | bool | None,
    finding: Any,
) -> Optional[XssVerdictOverride]:
    """产出是否覆盖 LLM verdict；None 表示不强制改判。"""
    src = normalize_src_type(src_type)
    cls = classification.classification

    if cls == XssClass.NOT_XSS:
        return None

    # Edu 反射硬忽略（优先级最高）
    if src == "edusrc" and classification.is_reflected:
        return XssVerdictOverride(
            force_verdict="ignored",
            classification=XssClass.LOW_IMPACT_XSS if cls == XssClass.VALID_XSS else cls,
            reason=EDU_REFLECTED_BLOCK_REASON,
            ignore_reason="EduSRC不收反射型XSS",
            block_deepen_rescue=True,
        )

    if cls == XssClass.SELF_XSS:
        return XssVerdictOverride(
            force_verdict="ignored",
            classification=cls,
            reason=classification.reason,
            ignore_reason="Self-XSS/仅攻击者可触发",
            block_deepen_rescue=True,
        )

    if cls == XssClass.HTML_INJECTION:
        return XssVerdictOverride(
            force_verdict="ignored",
            classification=cls,
            reason=classification.reason,
            ignore_reason="仅HTML注入无法执行JavaScript",
            block_deepen_rescue=True,
        )

    if cls == XssClass.OUT_OF_SCOPE_ORIGIN:
        return XssVerdictOverride(
            force_verdict="ignored",
            classification=cls,
            reason=classification.reason,
            ignore_reason="执行Origin不在目标安全边界且无跨域信任",
            block_deepen_rescue=True,
        )

    if cls == XssClass.NON_EXECUTABLE_UPLOAD:
        # 上传点可能还能打 getshell → deepen；若明确只是下载则 ignored
        text = _blob(finding)
        if any(k in text for k in ("上传", "upload", "getshell", "webshell")):
            return XssVerdictOverride(
                force_verdict="deepen",
                classification=cls,
                reason=classification.reason,
                deepen_directive=(
                    "当前文件以 attachment/octet-stream 返回，不能当 XSS。"
                    "请验证能否上传可解析执行的脚本并访问拿命令回显（getshell），"
                    "或让服务器以 text/html 内联返回且非 attachment。"
                ),
                block_deepen_rescue=False,
            )
        return XssVerdictOverride(
            force_verdict="ignored",
            classification=cls,
            reason=classification.reason,
            ignore_reason="不可执行上传（强制下载/非HTML）",
            block_deepen_rescue=True,
        )

    if cls == XssClass.INSUFFICIENT_EVIDENCE:
        miss = classification.missing or ["最终URL", "Content-Type", "Origin", "他人可达性"]
        directive = (
            "XSS 证据不足，禁止假设 Cookie/CORS/他人访问。请补："
            + "；".join(miss)
            + "。补齐后按 Execution→Origin→Reachability→Impact 再交。"
        )
        return XssVerdictOverride(
            force_verdict="deepen",
            classification=cls,
            reason=classification.reason,
            deepen_directive=directive,
            block_deepen_rescue=False,
        )

    if cls == XssClass.LOW_IMPACT_XSS:
        return XssVerdictOverride(
            force_verdict="ignored",
            classification=cls,
            reason=classification.reason,
            ignore_reason="低影响XSS/不达收录门槛",
            block_deepen_rescue=True,
        )

    if cls == XssClass.VALID_XSS and classification.confidence == "high":
        # 仅在 LLM 误 ignored 时抬升；accepted/deepen 由 apply 层处理
        return XssVerdictOverride(
            force_verdict="accepted",
            classification=cls,
            reason=classification.reason,
            severity_final="中危",
            block_deepen_rescue=False,
        )

    return None


def xss_review_prompt(src_type: str | bool | None) -> str:
    if normalize_src_type(src_type) == "enterprise":
        return XSS_REVIEW_PROMPT_ENTERPRISE
    return XSS_REVIEW_PROMPT_EDU


def xss_worker_prompt(src_type: str | bool | None) -> str:
    if normalize_src_type(src_type) == "enterprise":
        return XSS_WORKER_PROMPT
    return XSS_WORKER_PROMPT_EDU


def edu_reflected_xss_block_reason(finding: Any) -> str:
    """Worker 提交拦截：Edu + 反射。"""
    if not looks_like_xss(finding) and not (
        getattr(getattr(finding, "self_check", None), "is_reflected_xss", False)
    ):
        return ""
    if _is_reflected(finding):
        return EDU_REFLECTED_BLOCK_REASON
    return ""


def xss_missing_evidence_reason(finding: Any) -> str:
    """Worker 提交拦截：XSS 类缺最终 URL / Content-Type。"""
    if not looks_like_xss(finding):
        return ""
    if _is_reflected(finding):
        # 反射由 edu 拦截或企业允许；这里不因缺 CT 拦反射（反射常在查询响应里）
        return ""
    cls = classify_xss(finding)
    if cls.classification in {
        XssClass.SELF_XSS, XssClass.HTML_INJECTION, XssClass.OUT_OF_SCOPE_ORIGIN,
        XssClass.NON_EXECUTABLE_UPLOAD, XssClass.VALID_XSS, XssClass.NOT_XSS,
    }:
        return ""
    # 存储/上传类缺关键头
    text = _blob(finding)
    uploadish = any(k in text for k in ("上传", "upload", "存储型", "stored"))
    xc = _xss_check_dict(finding)
    subtype = _s(xc.get("subtype")).lower()
    if subtype in {"upload", "stored", "third_party_storage", "markdown"} or uploadish:
        exec_url = _pick_execution_url(finding)
        ct = _content_type(finding)
        if not exec_url or not ct:
            return XSS_MISSING_EVIDENCE_GUIDANCE
    if cls.classification == XssClass.INSUFFICIENT_EVIDENCE and cls.missing:
        if any("Content-Type" in m or "URL" in m or "origin" in m.lower() for m in cls.missing):
            return XSS_MISSING_EVIDENCE_GUIDANCE
    return ""


def apply_xss_override_to_review(review: Any, override: XssVerdictOverride) -> None:
    """把覆盖写进 Review 对象（就地修改）。"""
    from app.schemas import Confidence, ReviewVerdict, Severity

    note = f"[XSS判定] {override.classification.value}：{override.reason}"
    review.reviewer_notes = ((getattr(review, "reviewer_notes", None) or "").strip() + "\n" + note).strip()

    if override.force_verdict == "ignored":
        review.verdict = ReviewVerdict.ignored
        review.confidence = Confidence.likely
        review.severity_final = None
        review.score = min(float(getattr(review, "score", 0) or 0), 2.0)
        reasons = list(getattr(review, "ignore_reasons", None) or [])
        if override.ignore_reason and override.ignore_reason not in reasons:
            reasons.append(override.ignore_reason)
        review.ignore_reasons = reasons
        review.deepen_directive = ""
    elif override.force_verdict == "deepen":
        review.verdict = ReviewVerdict.deepen
        review.confidence = Confidence.uncertain
        review.severity_final = None
        review.score = min(max(float(getattr(review, "score", 0) or 0), 2.5), 3.9)
        review.deepen_directive = override.deepen_directive or review.deepen_directive or XSS_MISSING_EVIDENCE_GUIDANCE
        review.ignore_reasons = []
    elif override.force_verdict == "accepted":
        # 仅抬升误判 ignored；deepen 留给证据链
        if getattr(review, "verdict", None) == ReviewVerdict.ignored:
            review.verdict = ReviewVerdict.accepted
            review.confidence = Confidence.likely
            sev = override.severity_final or "中危"
            try:
                review.severity_final = Severity(sev)
            except Exception:
                review.severity_final = Severity.medium
            review.score = min(max(float(getattr(review, "score", 0) or 0), 5.0), 6.5)
            review.ignore_reasons = []
            review.reviewer_notes = (
                (review.reviewer_notes or "").strip()
                + "\n[系统改判] 高置信 VALID_XSS（目标 Origin + 可执行 Content-Type），不得因缺弹窗/缺 Cookie 读取而 ignored。"
            ).strip()
