"""直接读取可移植知识库目录（kb/），无需 app.db。

布局：
  kb/{slug}/meta.json + report.md + poc/ + nuclei/ + exp/
"""

from __future__ import annotations

import json
import threading
import time
import uuid
import zlib
from copy import deepcopy
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from . import nuclei, poc
from .errors import (
    DEFAULT_MAX_CHARS,
    DEFAULT_NUCLEI_OUTPUT_CHARS,
    DEFAULT_NUCLEI_TIMEOUT,
    DEFAULT_POC_OUTPUT_CHARS,
    DEFAULT_POC_TIMEOUT,
    DEFAULT_SEARCH_LIMIT,
    DEFAULT_SEARCH_SEVERITIES,
    HARD_CHUNK_MAX,
    HARD_NUCLEI_OUTPUT_MAX,
    HARD_POC_OUTPUT_MAX,
    MAX_NUCLEI_VULNS,
    MAX_SEARCH_LIMIT,
    NUCLEI_JOB_TTL_S,
    POC_JOB_TTL_S,
    VulnKbError,
    _POC_SCRIPT_PREFERENCE,
)

ArtifactKind = Literal["report", "poc", "nuclei", "exp"]

_POC_SKIP_DIRS = frozenset({"logs", "__pycache__", ".git", "node_modules"})
_POC_SKIP_NAMES = frozenset({"result.json", "env.json", "vuln.json", "failure_reason.md"})
_TEXT_EXTS = frozenset(
    {
        ".py",
        ".md",
        ".txt",
        ".json",
        ".yml",
        ".yaml",
        ".xml",
        ".sql",
        ".sh",
        ".bash",
        ".js",
        ".ts",
        ".go",
        ".java",
        ".jsp",
        ".html",
        ".css",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".b64",
        ".payload",
    }
)

_nuclei_jobs_lock = threading.Lock()
_nuclei_jobs: dict[str, dict[str, Any]] = {}
_poc_jobs_lock = threading.Lock()
_poc_jobs: dict[str, dict[str, Any]] = {}


@dataclass
class ArtifactFileInfo:
    path: str
    size: int


@dataclass
class KbFsEntry:
    id: int
    slug: str
    root: Path
    identifier: str
    title: str
    summary: str | None
    component: str | None
    vuln_type: str | None
    severity: str | None
    source_url: str | None
    affected_versions: str | None


_store_lock = threading.Lock()
_store_root: Path | None = None
_store_entries: list[KbFsEntry] = []
_store_by_id: dict[int, KbFsEntry] = {}


def _stable_id(identifier: str) -> int:
    h = zlib.crc32(identifier.strip().encode("utf-8")) & 0x7FFFFFFF
    return h or 1


def _parse_severities(severity: str | None) -> list[str]:
    if severity is None or not str(severity).strip():
        return list(DEFAULT_SEARCH_SEVERITIES)
    parts = [p.strip().lower() for p in str(severity).replace("+", ",").split(",")]
    return [p for p in parts if p] or list(DEFAULT_SEARCH_SEVERITIES)


def _pick_default_poc_script(scripts: list[str]) -> str | None:
    if not scripts:
        return None
    lower_map = {s.lower(): s for s in scripts}
    for name in _POC_SCRIPT_PREFERENCE:
        if name in lower_map:
            return lower_map[name]
    roots = [s for s in scripts if "/" not in s]
    return roots[0] if roots else scripts[0]


def _clip_output(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    keep = max(0, max_chars - 32)
    return text[:keep] + "\n…(output truncated)\n", True


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _iter_entry_dirs(root: Path) -> list[Path]:
    if not root.exists():
        return []
    if (root / "meta.json").is_file():
        return [root]
    entries: list[Path] = []
    seen: set[Path] = set()
    for base in (root / "kb", root):
        if not base.is_dir():
            continue
        for child in sorted(base.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            if child.name.lower() in {"readme.md", "readme"}:
                continue
            if (child / "meta.json").is_file():
                resolved = child.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    entries.append(child)
    return entries


def _entry_from_dir(entry_dir: Path) -> KbFsEntry | None:
    meta = _load_json(entry_dir / "meta.json")
    if not meta:
        return None
    identifier = str(meta.get("identifier") or "").strip()
    if not identifier:
        return None
    vid = _stable_id(identifier)
    return KbFsEntry(
        id=vid,
        slug=entry_dir.name,
        root=entry_dir.resolve(),
        identifier=identifier,
        title=str(meta.get("title") or identifier)[:512],
        summary=meta.get("summary") if isinstance(meta.get("summary"), str) else None,
        component=meta.get("component") if isinstance(meta.get("component"), str) else None,
        vuln_type=meta.get("vuln_type") if isinstance(meta.get("vuln_type"), str) else None,
        severity=meta.get("severity") if isinstance(meta.get("severity"), str) else None,
        source_url=meta.get("source_url") if isinstance(meta.get("source_url"), str) else None,
        affected_versions=(
            meta.get("affected_versions")
            if isinstance(meta.get("affected_versions"), str)
            else None
        ),
    )


def bind(kb_dir: str | Path) -> Path:
    root = Path(kb_dir).expanduser().resolve()
    if not root.is_dir():
        raise VulnKbError(f"kb dir not found: {root}", code="not_found")

    entries: list[KbFsEntry] = []
    by_id: dict[int, KbFsEntry] = {}
    for d in _iter_entry_dirs(root):
        ent = _entry_from_dir(d)
        if not ent:
            continue
        while ent.id in by_id and by_id[ent.id].identifier != ent.identifier:
            ent.id = _stable_id(f"{ent.identifier}:{ent.slug}:{ent.id}")
        entries.append(ent)
        by_id[ent.id] = ent

    entries.sort(key=lambda e: e.identifier, reverse=True)
    with _store_lock:
        global _store_root, _store_entries, _store_by_id
        _store_root = root
        _store_entries = entries
        _store_by_id = by_id
    return root


def bound_root() -> Path | None:
    with _store_lock:
        return _store_root


def _require_bound() -> tuple[Path, list[KbFsEntry], dict[int, KbFsEntry]]:
    with _store_lock:
        if _store_root is None:
            raise VulnKbError("kb dir not bound; pass --kb-dir", code="bad_request")
        return _store_root, list(_store_entries), dict(_store_by_id)


def resolve_vuln_id(key: int | str) -> int:
    _, entries, by_id = _require_bound()
    raw = str(key).strip()
    if not raw:
        raise VulnKbError("vuln id is required", code="bad_request")
    if raw.isdigit():
        vid = int(raw)
        if vid in by_id:
            return vid
        raise VulnKbError(f"vulnerability not found: {vid}", code="not_found")
    low = raw.casefold()
    for ent in entries:
        if ent.identifier.casefold() == low or ent.slug.casefold() == low:
            return ent.id
    raise VulnKbError(f"vulnerability not found: {raw}", code="not_found")


def _get_entry(vuln_id: int | str) -> KbFsEntry:
    _, _, by_id = _require_bound()
    if isinstance(vuln_id, int):
        ent = by_id.get(int(vuln_id))
        if not ent:
            raise VulnKbError(f"vulnerability not found: {vuln_id}", code="not_found")
        return ent
    vid = resolve_vuln_id(vuln_id)
    ent = by_id.get(vid)
    if not ent:
        raise VulnKbError("vulnerability not found", code="not_found")
    return ent


def _is_under(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _kind_root(ent: KbFsEntry, kind: ArtifactKind) -> Path | None:
    if kind == "report":
        p = ent.root / "report.md"
        return p if p.is_file() else None
    p = ent.root / kind
    return p if p.exists() else None


def _list_files(ent: KbFsEntry, kind: ArtifactKind) -> list[ArtifactFileInfo]:
    root = _kind_root(ent, kind)
    if root is None:
        return []
    files: list[Path] = []
    if kind == "report":
        files = [root]
    elif kind == "poc":
        if not root.is_dir():
            return []
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            rel_parts = p.relative_to(root).parts
            if any(part in _POC_SKIP_DIRS for part in rel_parts):
                continue
            if p.name in _POC_SKIP_NAMES or p.name.startswith("."):
                continue
            files.append(p)
    elif kind == "nuclei":
        if root.is_dir():
            files = [
                p
                for p in sorted(root.rglob("*"))
                if p.is_file()
                and not p.name.startswith(".")
                and p.suffix.lower() in {".yml", ".yaml"}
            ]
    else:
        if root.is_dir():
            for p in sorted(root.rglob("*")):
                if not p.is_file() or p.name.startswith("."):
                    continue
                if p.suffix.lower() in _TEXT_EXTS or p.suffix.lower() in {".go", ".yml", ".yaml"}:
                    files.append(p)

    out: list[ArtifactFileInfo] = []
    for p in files:
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        if kind == "report":
            rel = "report.md"
        else:
            rel = str(p.relative_to(root)).replace("\\", "/")
        out.append(ArtifactFileInfo(path=rel, size=size))
    return out


def _resolve_file_across_kinds(
    ent: KbFsEntry, rel_path: str
) -> tuple[str, ArtifactKind, Path]:
    if not rel_path or not str(rel_path).strip():
        raise VulnKbError("path is required", code="bad_request")
    rel_norm = rel_path.replace("\\", "/").lstrip("/")
    if not rel_norm or ".." in Path(rel_norm).parts:
        raise VulnKbError("path traversal rejected", code="bad_path")

    hits: list[tuple[ArtifactKind, str, Path]] = []
    available: list[str] = []
    for kind in ("report", "poc", "nuclei", "exp"):
        kind_t: ArtifactKind = kind  # type: ignore[assignment]
        listed = _list_files(ent, kind_t)
        root = _kind_root(ent, kind_t)
        if root is None:
            continue
        for info in listed:
            available.append(f"{kind}:{info.path}")
            if info.path != rel_norm:
                continue
            if kind == "report":
                target = root
            else:
                target = (root / info.path).resolve()
                if not _is_under(root, target) or not target.is_file():
                    continue
            hits.append((kind_t, info.path, target))

    if not hits:
        hint = ", ".join(available[:30]) if available else "(none)"
        raise VulnKbError(
            f"file not found: {rel_norm}. available: {hint}",
            code="not_found",
        )
    if len(hits) > 1:
        kinds = ", ".join(sorted({h[0] for h in hits}))
        raise VulnKbError(
            f"path {rel_norm!r} matches multiple kinds ({kinds}); "
            "rename/disambiguate or pick a unique relative path",
            code="ambiguous",
        )
    return hits[0]


def list_components(
    *,
    q: str | None = None,
    limit: int = 0,
) -> dict[str, Any]:
    """列出知识库中的不重复组件（可模糊过滤）。limit<=0 表示不截断。"""
    _, entries, _ = _require_bound()
    term = (q or "").strip().casefold()
    counts: dict[str, int] = {}
    canonical: dict[str, str] = {}
    for ent in entries:
        comp = (ent.component or "").strip()
        if not comp:
            continue
        key = comp.casefold()
        if term and term not in key:
            continue
        if key not in canonical:
            canonical[key] = comp
        counts[key] = counts.get(key, 0) + 1

    items = [
        {"component": canonical[k], "count": counts[k]}
        for k in sorted(canonical.keys())
    ]
    total = len(items)
    cap = int(limit or 0)
    if cap > 0:
        items = items[:cap]
    q_term = (q or "").strip() or None
    out: dict[str, Any] = {
        "count": len(items),
        "total": total,
        "limit": cap if cap > 0 else None,
    }
    # 有 -q 时只返回业务字段，省略回显与路径元数据
    if not q_term:
        out["q"] = None
        out["source"] = "kb-dir"
        out["kb_dir"] = str(bound_root())
    out["items"] = items
    return out


def search_vulns(
    *,
    component: str | None = None,
    severity: str | None = "critical",
    limit: int = DEFAULT_SEARCH_LIMIT,
) -> dict[str, Any]:
    _, entries, _ = _require_bound()
    limit = max(1, min(int(limit or DEFAULT_SEARCH_LIMIT), MAX_SEARCH_LIMIT))
    severities = _parse_severities(severity)
    comp = (component or "").strip().casefold()

    items: list[dict[str, Any]] = []
    for ent in entries:
        sev = (ent.severity or "").casefold()
        if severities and sev not in severities:
            continue
        if comp and comp not in (ent.component or "").casefold():
            continue
        items.append(
            {
                "id": ent.id,
                "identifier": ent.identifier,
                "title": ent.title,
                "component": ent.component,
                "vuln_type": ent.vuln_type,
                "severity": ent.severity,
                "slug": ent.slug,
            }
        )

    total = len(items)
    items = items[:limit]
    return {
        "count": len(items),
        "total": total,
        "limit": limit,
        "status_filter": "completed",
        "severity_filter": severities,
        "source": "kb-dir",
        "kb_dir": str(bound_root()),
        "items": items,
    }


def get_vuln(*, vuln_id: int | str) -> dict[str, Any]:
    ent = _get_entry(vuln_id)
    files: dict[str, list[dict[str, Any]]] = {}
    for kind in ("report", "poc"):
        files[kind] = [asdict(f) for f in _list_files(ent, kind)]  # type: ignore[arg-type]
    return {
        "id": ent.id,
        "identifier": ent.identifier,
        "title": ent.title,
        "summary": ent.summary,
        "component": ent.component,
        "vuln_type": ent.vuln_type,
        "severity": ent.severity,
        "source_url": ent.source_url,
        "affected_versions": ent.affected_versions,
        "slug": ent.slug,
        "files": files,
        "source": "kb-dir",
    }


def get_artifact(
    *,
    vuln_id: int | str,
    path: str,
    offset: int = 0,
    max_chars: int = DEFAULT_MAX_CHARS,
    full: bool = False,
) -> dict[str, Any]:
    ent = _get_entry(vuln_id)
    rel, kind, file_path = _resolve_file_across_kinds(ent, path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise VulnKbError(f"read failed: {exc}", code="io_error") from exc

    total = len(text)
    offset = max(0, int(offset or 0))
    if offset > total:
        offset = total
    if full or max_chars == 0:
        chunk_size = HARD_CHUNK_MAX
    else:
        chunk_size = max(1, min(int(max_chars), HARD_CHUNK_MAX))
    end = min(total, offset + chunk_size)
    content = text[offset:end]
    truncated = end < total
    return {
        "vuln_id": ent.id,
        "identifier": ent.identifier,
        "kind": kind,
        "path": rel,
        "offset": offset,
        "next_offset": end if truncated else None,
        "max_chars": chunk_size,
        "total_chars": total,
        "truncated": truncated,
        "content": content,
        "source": "kb-dir",
    }


def get_poc_meta_mcp(*, vuln_id: int | str) -> dict[str, Any]:
    ent = _get_entry(vuln_id)
    root = ent.root / "poc"
    if not root.is_dir():
        raise VulnKbError("no runnable python poc scripts", code="not_found")
    scripts: list[dict[str, Any]] = []
    for path in poc.list_python_pocs(root):
        rel = str(path.relative_to(root.resolve())).replace("\\", "/")
        description, args, _parse_ok = poc.parse_argparse_script(path)
        slim_args: list[dict[str, Any]] = []
        for a in args:
            flag = poc.prefer_cli_flag(a.get("flags") or [])
            if not flag:
                continue
            slim_args.append(
                {
                    "flag": flag,
                    "required": bool(a.get("required")),
                    "arg_type": a.get("arg_type") or "str",
                    "help": a.get("help"),
                }
            )
        scripts.append({"path": rel, "description": description, "args": slim_args})
    if not scripts:
        raise VulnKbError("no runnable python poc scripts", code="not_found")
    return {
        "vuln_id": ent.id,
        "identifier": ent.identifier,
        "scripts": scripts,
        "source": "kb-dir",
    }


def _purge_poc_jobs(now: float | None = None) -> None:
    ts = time.time() if now is None else now
    stale = [
        jid
        for jid, job in _poc_jobs.items()
        if ts - float(job.get("updated_at") or job.get("created_at") or 0) > POC_JOB_TTL_S
    ]
    for jid in stale:
        _poc_jobs.pop(jid, None)


def _poc_job_public(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "vuln_id": job.get("vuln_id"),
        "identifier": job.get("identifier"),
        "command": list(job.get("command") or []),
        "exit_code": job.get("exit_code"),
        "timed_out": bool(job.get("timed_out")),
        "stdout": job.get("stdout") or "",
        "stderr": job.get("stderr") or "",
        "max_output_chars": job.get("max_output_chars"),
        "error": job.get("error"),
        "source": "kb-dir",
    }


def _poc_worker(job_id: str) -> None:
    with _poc_jobs_lock:
        job = _poc_jobs.get(job_id)
        if not job:
            return
        job["status"] = "running"
        job["updated_at"] = time.time()
        poc_root = Path(str(job["_poc_root"]))
        script_rel = str(job["_script"])
        extra = list(job["_extra"])
        timeout_s = int(job["_timeout"])
        out_limit = int(job["max_output_chars"])

    try:
        try:
            result = poc.run_poc_script(
                poc_root,
                script_rel,
                extra_args=extra,
                timeout=timeout_s,
            )
        except ValueError as exc:
            with _poc_jobs_lock:
                job = _poc_jobs.get(job_id)
                if job:
                    job["status"] = "failed"
                    job["error"] = str(exc)
                    job["updated_at"] = time.time()
            return

        stdout, _ = _clip_output(result.get("stdout") or "", out_limit)
        stderr, _ = _clip_output(result.get("stderr") or "", out_limit)
        with _poc_jobs_lock:
            job = _poc_jobs.get(job_id)
            if not job:
                return
            job["command"] = result.get("command") or []
            job["exit_code"] = result.get("exit_code")
            job["timed_out"] = bool(result.get("timed_out"))
            job["stdout"] = stdout
            job["stderr"] = stderr
            job["status"] = "done"
            job["updated_at"] = time.time()
    except Exception as exc:  # noqa: BLE001
        with _poc_jobs_lock:
            job = _poc_jobs.get(job_id)
            if job:
                job["status"] = "failed"
                job["error"] = str(exc)
                job["updated_at"] = time.time()


def run_poc_mcp(
    *,
    vuln_id: int | str,
    args: dict[str, Any],
    script: str | None = None,
    timeout: int | None = None,
    max_output_chars: int = DEFAULT_POC_OUTPUT_CHARS,
) -> dict[str, Any]:
    if args is None or not isinstance(args, dict):
        raise VulnKbError("args must be an object of CLI flags", code="bad_request")
    try:
        extra = poc.flag_args_to_argv(args)
    except ValueError as exc:
        raise VulnKbError(str(exc), code="bad_request") from exc

    timeout_s = int(timeout) if timeout is not None else DEFAULT_POC_TIMEOUT
    if timeout_s < 1 or timeout_s > 600:
        raise VulnKbError("timeout must be 1–600 seconds", code="bad_request")

    out_limit = int(max_output_chars or DEFAULT_POC_OUTPUT_CHARS)
    if out_limit <= 0:
        out_limit = DEFAULT_POC_OUTPUT_CHARS
    out_limit = min(out_limit, HARD_POC_OUTPUT_MAX)

    ent = _get_entry(vuln_id)
    root = ent.root / "poc"
    listed = [
        str(p.relative_to(root.resolve())).replace("\\", "/")
        for p in poc.list_python_pocs(root)
    ]
    if not listed:
        raise VulnKbError("no runnable python poc scripts", code="not_found")
    script_rel = (script or "").strip() or None
    if not script_rel:
        script_rel = _pick_default_poc_script(listed)
    if not script_rel:
        raise VulnKbError("no poc script selected", code="bad_request")
    try:
        poc.resolve_poc_script(root, script_rel)
    except ValueError as exc:
        raise VulnKbError(str(exc), code="bad_request") from exc

    job_id = uuid.uuid4().hex
    now = time.time()
    job: dict[str, Any] = {
        "job_id": job_id,
        "status": "pending",
        "vuln_id": ent.id,
        "identifier": ent.identifier,
        "command": [],
        "exit_code": None,
        "timed_out": False,
        "stdout": "",
        "stderr": "",
        "max_output_chars": out_limit,
        "error": None,
        "created_at": now,
        "updated_at": now,
        "_poc_root": str(root),
        "_script": script_rel,
        "_extra": extra,
        "_timeout": timeout_s,
    }
    with _poc_jobs_lock:
        _purge_poc_jobs(now)
        _poc_jobs[job_id] = job

    thread = threading.Thread(
        target=_poc_worker,
        args=(job_id,),
        name=f"poc-job-{job_id[:8]}",
        daemon=True,
    )
    thread.start()
    return {
        "job_id": job_id,
        "message": "已启动后台 PoC；用 get_poc_result(job_id) 轮询结果。",
        "source": "kb-dir",
    }


def get_poc_result(*, job_id: str) -> dict[str, Any]:
    jid = str(job_id or "").strip()
    if not jid:
        raise VulnKbError("job_id is required", code="bad_request")
    with _poc_jobs_lock:
        _purge_poc_jobs()
        job = _poc_jobs.get(jid)
        if not job:
            raise VulnKbError("poc job not found or expired", code="not_found")
        return _poc_job_public(job)


def _purge_nuclei_jobs(now: float | None = None) -> None:
    ts = time.time() if now is None else now
    stale = [
        jid
        for jid, job in _nuclei_jobs.items()
        if ts - float(job.get("updated_at") or job.get("created_at") or 0) > NUCLEI_JOB_TTL_S
    ]
    for jid in stale:
        _nuclei_jobs.pop(jid, None)


def _nuclei_item_summary(
    item: dict[str, Any],
    *,
    hit: bool = False,
    skipped: bool = False,
    reason: str | None = None,
    timed_out: bool = False,
    error: str | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "vuln_id": item["vuln_id"],
        "identifier": item["identifier"],
        "title": item["title"],
        "hit": bool(hit),
    }
    if skipped:
        out["skipped"] = True
        if reason:
            out["reason"] = reason
    if timed_out:
        out["timed_out"] = True
    if error:
        out["error"] = error
    return out


def _run_one_nuclei_item(
    *,
    item: dict[str, Any],
    targets: list[str],
    extra: list[str],
    out_limit: int,
    per_timeout: int,
    nuclei_bin: str,
) -> dict[str, Any]:
    del out_limit
    templates = [Path(p) for p in (item.get("templates") or [])]
    if not templates:
        return _nuclei_item_summary(item, hit=False, skipped=True, reason="无 nuclei 模板")

    try:
        run = nuclei.run_nuclei_on_templates(
            targets,
            templates,
            extra_flags=extra,
            timeout=per_timeout,
            nuclei_bin=nuclei_bin,
        )
    except nuclei.NucleiRunnerError as exc:
        return _nuclei_item_summary(item, hit=False, error=exc.message)

    return _nuclei_item_summary(
        item,
        hit=bool(run.get("hit")),
        timed_out=bool(run.get("timed_out")),
        error=run.get("error"),
    )


def run_nuclei(
    *,
    vuln_ids: list[int | str],
    target: str,
    extra_flags: str | None = None,
    timeout: int | None = None,
    max_output_chars: int = DEFAULT_NUCLEI_OUTPUT_CHARS,
) -> dict[str, Any]:
    if not vuln_ids:
        raise VulnKbError("vuln_ids is required", code="bad_request")
    ids: list[int] = []
    seen: set[int] = set()
    for raw in vuln_ids:
        vid = resolve_vuln_id(raw)
        if vid in seen:
            continue
        seen.add(vid)
        ids.append(vid)
    if len(ids) > MAX_NUCLEI_VULNS:
        raise VulnKbError(
            f"vuln_ids too many (max {MAX_NUCLEI_VULNS}, got {len(ids)})",
            code="bad_request",
        )

    targets = [t.strip() for t in str(target or "").splitlines() if t.strip()]
    if not targets:
        raise VulnKbError("target is required (URL / host, one per line)", code="bad_request")

    timeout_s = int(timeout) if timeout is not None else DEFAULT_NUCLEI_TIMEOUT
    if timeout_s < 1 or timeout_s > 3600:
        raise VulnKbError("timeout must be 1–3600 seconds", code="bad_request")

    out_limit = int(max_output_chars or DEFAULT_NUCLEI_OUTPUT_CHARS)
    if out_limit <= 0:
        out_limit = DEFAULT_NUCLEI_OUTPUT_CHARS
    out_limit = min(out_limit, HARD_NUCLEI_OUTPUT_MAX)

    extra = nuclei.split_extra_flags(extra_flags)
    if len(extra) > 64:
        raise VulnKbError("extra_flags too long (max 64 tokens)", code="bad_request")

    per_vuln: list[dict[str, Any]] = []
    total_templates = 0
    for vid in ids:
        ent = _get_entry(vid)
        nuclei_root = ent.root / "nuclei"
        templates = nuclei.list_nuclei_templates(nuclei_root)
        rels: list[str] = []
        for t in templates:
            try:
                rels.append(str(t.relative_to(nuclei_root)).replace("\\", "/"))
            except ValueError:
                rels.append(t.name)
        total_templates += len(templates)
        per_vuln.append(
            {
                "vuln_id": ent.id,
                "identifier": ent.identifier,
                "title": ent.title,
                "templates": [str(p) for p in templates],
                "template_paths": rels,
            }
        )

    if total_templates == 0:
        raise VulnKbError(
            "no nuclei templates among selected vulns",
            code="not_found",
        )

    try:
        nuclei_bin = nuclei.find_nuclei()
    except nuclei.NucleiRunnerError as exc:
        raise VulnKbError(exc.message, code=exc.code) from exc

    with_templates = sum(1 for x in per_vuln if x["templates"])
    per_timeout = max(30, timeout_s // max(1, with_templates))

    job_id = uuid.uuid4().hex
    now = time.time()
    job = {
        "job_id": job_id,
        "status": "pending",
        "target": targets,
        "vuln_ids": ids,
        "template_count": total_templates,
        "total": len(per_vuln),
        "completed": 0,
        "hit_count": 0,
        "results": [],
        "error": None,
        "max_output_chars": out_limit,
        "created_at": now,
        "updated_at": now,
        "_per_vuln": per_vuln,
        "_extra": extra,
        "_per_timeout": per_timeout,
        "_nuclei_bin": nuclei_bin,
    }
    with _nuclei_jobs_lock:
        _purge_nuclei_jobs(now)
        _nuclei_jobs[job_id] = job

    def _worker(jid: str) -> None:
        with _nuclei_jobs_lock:
            j = _nuclei_jobs.get(jid)
            if not j:
                return
            j["status"] = "running"
            j["updated_at"] = time.time()
            per = list(j["_per_vuln"])
            tgts = list(j["target"])
            ex = list(j["_extra"])
            ol = int(j["max_output_chars"])
            pt = int(j["_per_timeout"])
            nb = str(j["_nuclei_bin"])
        try:
            for item in per:
                result = _run_one_nuclei_item(
                    item=item,
                    targets=tgts,
                    extra=ex,
                    out_limit=ol,
                    per_timeout=pt,
                    nuclei_bin=nb,
                )
                with _nuclei_jobs_lock:
                    j = _nuclei_jobs.get(jid)
                    if not j:
                        return
                    j["results"].append(result)
                    j["completed"] = int(j.get("completed") or 0) + 1
                    if result.get("hit"):
                        j["hit_count"] = int(j.get("hit_count") or 0) + 1
                    j["updated_at"] = time.time()
            with _nuclei_jobs_lock:
                j = _nuclei_jobs.get(jid)
                if j:
                    j["status"] = "done"
                    j["updated_at"] = time.time()
        except Exception as exc:  # noqa: BLE001
            with _nuclei_jobs_lock:
                j = _nuclei_jobs.get(jid)
                if j:
                    j["status"] = "failed"
                    j["error"] = str(exc)
                    j["updated_at"] = time.time()

    thread = threading.Thread(
        target=_worker,
        args=(job_id,),
        name=f"nuclei-job-{job_id[:8]}",
        daemon=True,
    )
    thread.start()
    return {
        "job_id": job_id,
        "message": "已启动后台扫描；用 get_nuclei_result(job_id) 轮询，完成后看 results[].hit。",
        "source": "kb-dir",
    }


def get_nuclei_result(*, job_id: str) -> dict[str, Any]:
    jid = str(job_id or "").strip()
    if not jid:
        raise VulnKbError("job_id is required", code="bad_request")
    with _nuclei_jobs_lock:
        _purge_nuclei_jobs()
        job = _nuclei_jobs.get(jid)
        if not job:
            raise VulnKbError("nuclei job not found or expired", code="not_found")
        status = str(job.get("status") or "")
        if status in ("pending", "running"):
            return {"job_id": job["job_id"], "status": "running", "source": "kb-dir"}
        return {
            "job_id": job["job_id"],
            "status": job["status"],
            "target": list(job.get("target") or []),
            "total": int(job.get("total") or 0),
            "completed": int(job.get("completed") or 0),
            "hit_count": int(job.get("hit_count") or 0),
            "results": deepcopy(job.get("results") or []),
            "error": job.get("error"),
            "source": "kb-dir",
        }
