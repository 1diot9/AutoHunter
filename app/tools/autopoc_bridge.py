"""AutoPoc 漏洞知识库桥接：供 Worker 三个工具调用。

直接 import vendored `tools/autopoc-kb/autopoc_kb`（零第三方依赖），
在参数校验失败时返回带 example / allowed / guidance 的纠错结构。
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_PKG = _REPO_ROOT / "tools" / "autopoc-kb"
_DEFAULT_KB = _REPO_ROOT / "data" / "autopoc-kb"

_READ_ACTIONS = ("get", "artifact", "poc_meta")
_RUN_ACTIONS = ("nuclei", "poc")
_SEARCH_ACTIONS = ("list_components", "search")
_SEVERITIES = ("critical", "high", "medium", "low")

_POLL_INTERVAL = 1.0
_ARTIFACT_MAX_CHARS = 6000  # 回传 LLM 再截一层，防 context 膨胀


def _env_path(name: str, default: Path) -> Path:
    raw = (os.environ.get(name) or "").strip()
    return Path(raw).expanduser() if raw else default


def package_dir() -> Path:
    return _env_path("AUTOPOC_KB_PKG_DIR", _DEFAULT_PKG)


def kb_dir() -> Path:
    return _env_path("AUTOPOC_KB_DIR", _DEFAULT_KB)


def _ensure_import_path() -> None:
    pkg = str(package_dir())
    if pkg not in sys.path:
        sys.path.insert(0, pkg)


def available() -> bool:
    """KB 包可导入且 kb_dir 下至少有一个含 meta.json 的条目时为 True。"""
    try:
        _ensure_import_path()
        root = kb_dir()
        if not root.is_dir():
            return False
        for child in root.iterdir():
            if child.is_dir() and (child / "meta.json").is_file():
                return True
        return False
    except Exception:
        return False


def _bind_store():
    _ensure_import_path()
    from autopoc_kb import store  # type: ignore
    from autopoc_kb.errors import VulnKbError  # type: ignore

    root = kb_dir()
    if not root.is_dir():
        raise VulnKbError(
            f"AUTOPOC_KB_DIR 不存在或不是目录: {root}",
            code="not_configured",
        )
    store.bind(root)
    return store, VulnKbError


def _arg_error(
    *,
    tool: str,
    error: str,
    guidance: str,
    required_for_action: Optional[list[str]] = None,
    allowed: Optional[list[str]] = None,
    example: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ok": False,
        "kind": "arg_error",
        "tool": tool,
        "error": error,
        "guidance": guidance,
    }
    if required_for_action is not None:
        out["required_for_action"] = required_for_action
    if allowed is not None:
        out["allowed"] = allowed
    if example is not None:
        out["example"] = example
    return out


def _wrap_exc(tool: str, exc: Exception, VulnKbError) -> dict[str, Any]:
    if isinstance(exc, VulnKbError):
        return {
            "ok": False,
            "kind": "kb_error",
            "tool": tool,
            "code": getattr(exc, "code", "error"),
            "error": getattr(exc, "message", str(exc)),
            "guidance": (
                "核对 vuln_id/path/args 是否来自上一轮 search/get/poc_meta 返回值；"
                "不要臆造 CVE 或 flag。需要组件标签时先 autopoc_search(action=list_components)。"
            ),
        }
    return {
        "ok": False,
        "kind": "exception",
        "tool": tool,
        "error": f"{type(exc).__name__}: {exc}",
        "guidance": "知识库调用异常；改用 http_request/run_shell 自行验证，或检查 AUTOPOC_KB_DIR。",
    }


def _normalize_severity(raw: Any) -> tuple[Optional[str], Optional[dict[str, Any]]]:
    if raw is None or str(raw).strip() == "":
        return "critical", None
    text = str(raw).strip().lower().replace("+", ",")
    parts = [p.strip() for p in text.split(",") if p.strip()]
    bad = [p for p in parts if p not in _SEVERITIES]
    if bad:
        return None, _arg_error(
            tool="autopoc_search",
            error=f"非法 severity: {bad}",
            allowed=list(_SEVERITIES),
            guidance="severity 只能是 critical/high/medium/low，可用逗号组合，如 critical,high。",
            example={"action": "search", "component": "confluence", "severity": "critical,high", "limit": 10},
        )
    return ",".join(parts), None


def _wait_job(get_result, job_id: str, *, timeout_s: int) -> dict[str, Any]:
    deadline = time.time() + max(1, int(timeout_s))
    last: dict[str, Any] = {}
    while time.time() < deadline:
        last = get_result(job_id=job_id)
        status = str(last.get("status") or "")
        if status not in ("pending", "running"):
            return last
        time.sleep(_POLL_INTERVAL)
    last = dict(last or {})
    last["ok"] = False
    last["timed_out_waiting"] = True
    last["error"] = last.get("error") or f"等待任务结果超时（>{timeout_s}s）"
    last["guidance"] = "可减小 vuln_ids 数量或 timeout 后重试；或改用 http_request 手验。"
    return last


# ---- autopoc_search ----

def autopoc_search(
    *,
    action: str = "search",
    component: str = "",
    q: str = "",
    severity: Any = "critical",
    limit: int = 10,
) -> dict[str, Any]:
    action = (action or "search").strip().lower()
    if action not in _SEARCH_ACTIONS:
        return _arg_error(
            tool="autopoc_search",
            error=f"未知 action: {action!r}",
            allowed=list(_SEARCH_ACTIONS),
            guidance="action 只能是 list_components（列组件标签）或 search（按组件/关键词搜洞）。",
            example={"action": "search", "component": "confluence", "severity": "critical,high", "limit": 10},
        )

    try:
        store, VulnKbError = _bind_store()
    except Exception as exc:
        _ensure_import_path()
        try:
            from autopoc_kb.errors import VulnKbError as _E  # type: ignore
        except Exception:
            _E = Exception  # type: ignore
        return _wrap_exc("autopoc_search", exc, _E)

    try:
        if action == "list_components":
            data = store.list_components(q=(q or component or None) or None, limit=int(limit or 0))
            return {
                "ok": True,
                "action": action,
                "data": data,
                "guidance": (
                    "从 items[].component 选精确标签，再调用 "
                    "autopoc_search(action=search, component=标签)。"
                ),
            }

        sev, sev_err = _normalize_severity(severity)
        if sev_err:
            return sev_err
        comp = (component or "").strip()
        query = (q or "").strip()
        if not comp and not query:
            return _arg_error(
                tool="autopoc_search",
                error="search 需要 component 或 q",
                required_for_action=["component|q"],
                guidance=(
                    "已识别产品栈时填 component（如 confluence）；"
                    "不确定标签时先 action=list_components；"
                    "也可 q 填 CVE/标题关键词。"
                ),
                example={"action": "search", "component": "confluence", "severity": "critical,high", "limit": 10},
            )

        cap = max(1, min(int(limit or 10), 50))
        # 仅有 q（CVE/标题）时放宽 severity，避免默认 critical 漏掉条目
        use_sev = sev
        if query and not comp and (severity is None or str(severity).strip() in ("", "critical")):
            use_sev = "critical,high,medium,low"

        if comp and not query:
            data = store.search_vulns(component=comp, severity=use_sev, limit=cap)
        else:
            # 取一批再按 q 过滤 identifier/title/component/slug
            raw = store.search_vulns(
                component=comp or None,
                severity=use_sev,
                limit=50,
            )
            term = (query or comp).casefold()
            items = []
            for it in raw.get("items") or []:
                blob = " ".join(
                    str(it.get(k) or "") for k in ("identifier", "title", "component", "slug", "vuln_type")
                ).casefold()
                if term in blob:
                    items.append(it)
            data = {
                "count": len(items[:cap]),
                "total": len(items),
                "limit": cap,
                "status_filter": "completed",
                "severity_filter": (use_sev or "").split(","),
                "source": "kb-dir",
                "kb_dir": str(kb_dir()),
                "items": items[:cap],
            }

        return {
            "ok": True,
            "action": "search",
            "data": data,
            "guidance": (
                "从 items 选 id 或 identifier，用 autopoc_read(action=get, vuln_id=…) 看产物清单；"
                "扫描器 hit 不是 finding，必须再用 http_request 实证后才能 submit_finding。"
            ),
        }
    except Exception as exc:
        return _wrap_exc("autopoc_search", exc, VulnKbError)


# ---- autopoc_read ----

def autopoc_read(
    *,
    action: str = "get",
    vuln_id: Any = None,
    path: str = "",
    offset: int = 0,
    max_chars: int = _ARTIFACT_MAX_CHARS,
) -> dict[str, Any]:
    action = (action or "get").strip().lower()
    if action not in _READ_ACTIONS:
        return _arg_error(
            tool="autopoc_read",
            error=f"未知 action: {action!r}",
            allowed=list(_READ_ACTIONS),
            guidance="get=元数据+文件清单；artifact=读相对路径正文；poc_meta=可跑 PoC 的 flag 列表。",
            example={"action": "get", "vuln_id": "CVE-2024-21683"},
        )

    if vuln_id is None or str(vuln_id).strip() == "":
        return _arg_error(
            tool="autopoc_read",
            error="缺少 vuln_id",
            required_for_action=["vuln_id"] + (["path"] if action == "artifact" else []),
            guidance="vuln_id 必须来自 autopoc_search 返回的 id / identifier / slug，禁止臆造。",
            example={"action": action, "vuln_id": "CVE-2024-21683", **({"path": "report.md"} if action == "artifact" else {})},
        )

    if action == "artifact" and not (path or "").strip():
        return _arg_error(
            tool="autopoc_read",
            error="action=artifact 缺少 path",
            required_for_action=["vuln_id", "path"],
            guidance="先 action=get 看 files.report / files.poc 相对路径，再填 path（如 report.md）。",
            example={"action": "artifact", "vuln_id": str(vuln_id), "path": "report.md"},
        )

    try:
        store, VulnKbError = _bind_store()
    except Exception as exc:
        _ensure_import_path()
        try:
            from autopoc_kb.errors import VulnKbError as _E  # type: ignore
        except Exception:
            _E = Exception  # type: ignore
        return _wrap_exc("autopoc_read", exc, _E)

    try:
        vid = str(vuln_id).strip()
        if action == "get":
            data = store.get_vuln(vuln_id=vid)
            return {
                "ok": True,
                "action": action,
                "data": data,
                "guidance": (
                    "需要报告正文：autopoc_read(action=artifact, vuln_id=…, path=files 里的相对路径)；"
                    "要跑 PoC：先 poc_meta 再 autopoc_run。改编利用链，勿原样照抄历史 PoC。"
                ),
            }
        if action == "poc_meta":
            data = store.get_poc_meta_mcp(vuln_id=vid)
            return {
                "ok": True,
                "action": action,
                "data": data,
                "guidance": (
                    "args 的键必须是 scripts[].args[].flag（如 --url）；"
                    "bool true 表示只传 flag。然后 autopoc_run(action=poc, vuln_id=…, args={…})。"
                ),
            }
        # artifact
        chunk = max(500, min(int(max_chars or _ARTIFACT_MAX_CHARS), 12000))
        data = store.get_artifact(
            vuln_id=vid,
            path=path.strip(),
            offset=int(offset or 0),
            max_chars=chunk,
        )
        guidance = "结合目标环境改编利用；用 http_request 实证后再 submit_finding。"
        if data.get("truncated"):
            guidance = (
                f"正文已截断；用 offset={data.get('next_offset')} 再调 artifact 续读。"
                " " + guidance
            )
        return {"ok": True, "action": action, "data": data, "guidance": guidance}
    except Exception as exc:
        return _wrap_exc("autopoc_read", exc, VulnKbError)


# ---- autopoc_run ----

def autopoc_run(
    *,
    action: str = "nuclei",
    vuln_id: Any = None,
    vuln_ids: Any = None,
    target: str = "",
    args: Any = None,
    script: str = "",
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    action = (action or "nuclei").strip().lower()
    if action not in _RUN_ACTIONS:
        return _arg_error(
            tool="autopoc_run",
            error=f"未知 action: {action!r}",
            allowed=list(_RUN_ACTIONS),
            guidance="nuclei=按库内模板扫 target；poc=跑库内 Python PoC（args 键须来自 poc_meta）。",
            example={
                "action": "nuclei",
                "vuln_ids": ["CVE-2024-21683"],
                "target": "https://wiki.example.edu.cn",
            },
        )

    tgt = (target or "").strip()
    if not tgt:
        ids_hint: list[str] = []
        if vuln_ids is not None:
            norm = _normalize_vuln_ids(vuln_id=vuln_id, vuln_ids=vuln_ids)
            if isinstance(norm, list):
                ids_hint = norm
        elif vuln_id is not None and str(vuln_id).strip():
            ids_hint = [str(vuln_id).strip()]
        ex: dict[str, Any] = {
            "action": action,
            "target": "https://example.edu.cn",
        }
        if action == "nuclei":
            ex["vuln_ids"] = ids_hint or ["CVE-2024-21683"]
        else:
            ex["vuln_id"] = (ids_hint[0] if ids_hint else "CVE-2024-21683")
            ex["args"] = {"--url": "https://example.edu.cn"}
        return _arg_error(
            tool="autopoc_run",
            error="缺少 target",
            required_for_action=["target", "vuln_ids" if action == "nuclei" else "vuln_id", "args"],
            guidance="target 填当前授权目标 URL/host；仅对任务内目标使用。",
            example=ex,
        )

    try:
        store, VulnKbError = _bind_store()
    except Exception as exc:
        _ensure_import_path()
        try:
            from autopoc_kb.errors import VulnKbError as _E  # type: ignore
        except Exception:
            _E = Exception  # type: ignore
        return _wrap_exc("autopoc_run", exc, _E)

    try:
        if action == "nuclei":
            ids = _normalize_vuln_ids(vuln_id=vuln_id, vuln_ids=vuln_ids)
            if isinstance(ids, dict):
                return ids
            to = int(timeout) if timeout is not None else 300
            to = max(30, min(to, 600))
            started = store.run_nuclei(vuln_ids=ids, target=tgt, timeout=to)
            job_id = started.get("job_id")
            if not job_id:
                return {
                    "ok": False,
                    "tool": "autopoc_run",
                    "error": "run_nuclei 未返回 job_id",
                    "data": started,
                    "guidance": "检查 vuln_ids 是否有 nuclei 模板；改用 autopoc_read 读报告后手验。",
                }
            result = _wait_job(store.get_nuclei_result, str(job_id), timeout_s=to + 30)
            hits = [
                r for r in (result.get("results") or [])
                if isinstance(r, dict) and r.get("hit")
            ]
            return {
                "ok": True,
                "action": action,
                "data": result,
                "hit_count": len(hits),
                "guidance": (
                    "nuclei hit 只是线索，不是 finding。"
                    "对 hit 条目用 autopoc_read 读报告，再用 http_request 构造最小请求实证后才能 submit_finding。"
                ),
            }

        # poc
        vid = vuln_id if vuln_id is not None and str(vuln_id).strip() else None
        if vid is None and vuln_ids:
            norm = _normalize_vuln_ids(vuln_id=None, vuln_ids=vuln_ids)
            if isinstance(norm, dict):
                return norm
            vid = norm[0]
        if vid is None or str(vid).strip() == "":
            return _arg_error(
                tool="autopoc_run",
                error="action=poc 缺少 vuln_id",
                required_for_action=["vuln_id", "target", "args"],
                guidance="先 autopoc_read(action=poc_meta) 看 scripts 与 flag，再填 args。",
                example={
                    "action": "poc",
                    "vuln_id": "CVE-2024-21683",
                    "target": tgt,
                    "args": {"--url": tgt},
                },
            )
        if args is None:
            # 常见缺参：自动给带 target 的示例，并提示先 poc_meta
            return _arg_error(
                tool="autopoc_run",
                error="action=poc 缺少 args",
                required_for_action=["vuln_id", "args"],
                guidance=(
                    "args 须为 CLI flag 对象，键以 - 开头且与 poc_meta 一致。"
                    "先 autopoc_read(action=poc_meta, vuln_id=…)。"
                    "若 PoC 用 --url/--target，可把当前 target 填进去。"
                ),
                example={
                    "action": "poc",
                    "vuln_id": str(vid),
                    "target": tgt,
                    "args": {"--url": tgt},
                },
            )
        if not isinstance(args, dict):
            return _arg_error(
                tool="autopoc_run",
                error="args 必须是 JSON object",
                guidance='例如 {"--url":"https://…","--check":true}；键必须来自 poc_meta。',
                example={"action": "poc", "vuln_id": str(vid), "target": tgt, "args": {"--url": tgt}},
            )
        # 若模型只传了 target 忘了把 URL 放进 args，尝试补常见 flag（仍建议先 poc_meta）
        flag_args = dict(args)
        url_keys = ("--url", "--target", "-u", "--host")
        if not any(k in flag_args for k in url_keys):
            flag_args["--url"] = tgt

        to = int(timeout) if timeout is not None else 120
        to = max(10, min(to, 600))
        started = store.run_poc_mcp(
            vuln_id=str(vid).strip(),
            args=flag_args,
            script=(script or "").strip() or None,
            timeout=to,
        )
        job_id = started.get("job_id")
        if not job_id:
            return {
                "ok": False,
                "tool": "autopoc_run",
                "error": "run_poc 未返回 job_id",
                "data": started,
                "guidance": "核对 script/args；先 poc_meta。也可读 artifact 后手改编验证。",
            }
        result = _wait_job(store.get_poc_result, str(job_id), timeout_s=to + 30)
        return {
            "ok": True,
            "action": action,
            "data": result,
            "guidance": (
                "PoC 输出仅作参考；须用 http_request 复现最小证据链后再 submit_finding。"
                "不要把历史 PoC 原样当报告。"
            ),
        }
    except Exception as exc:
        return _wrap_exc("autopoc_run", exc, VulnKbError)


def _normalize_vuln_ids(*, vuln_id: Any, vuln_ids: Any) -> list[str] | dict[str, Any]:
    out: list[str] = []
    if vuln_ids is not None:
        if isinstance(vuln_ids, str):
            parts = [p.strip() for p in vuln_ids.replace(" ", ",").split(",") if p.strip()]
            out.extend(parts)
        elif isinstance(vuln_ids, list):
            for x in vuln_ids:
                s = str(x).strip()
                if s:
                    out.append(s)
        else:
            return _arg_error(
                tool="autopoc_run",
                error="vuln_ids 须为数组或逗号分隔字符串",
                required_for_action=["vuln_ids", "target"],
                example={"action": "nuclei", "vuln_ids": ["CVE-2024-21683"], "target": "https://example.edu.cn"},
                guidance="vuln_ids 来自 search 返回的 id/identifier，最多 10 条。",
            )
    if vuln_id is not None and str(vuln_id).strip():
        out.append(str(vuln_id).strip())
    # dedupe preserve order
    seen: set[str] = set()
    uniq: list[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    if not uniq:
        return _arg_error(
            tool="autopoc_run",
            error="缺少 vuln_ids（或 vuln_id）",
            required_for_action=["vuln_ids", "target"],
            guidance="先 autopoc_search 拿到候选，再把 id/identifier 列表传入（最多 10）。",
            example={"action": "nuclei", "vuln_ids": ["CVE-2024-21683"], "target": "https://example.edu.cn"},
        )
    if len(uniq) > 10:
        return _arg_error(
            tool="autopoc_run",
            error=f"vuln_ids 最多 10 条，当前 {len(uniq)}",
            guidance="缩小为最相关的几条再扫。",
            example={"action": "nuclei", "vuln_ids": uniq[:3], "target": "https://example.edu.cn"},
        )
    return uniq
