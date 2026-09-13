"""任务级测绘 API 调用计数（FOFA / Quake / Hunter 等）。"""
from __future__ import annotations

from threading import Lock
from typing import Any

from app.llm.usage import _write_runtime_stats

_LOCK = Lock()
_CALLS: dict[str, dict[str, Any]] = {}
_DIRTY: set[str] = set()


def _empty() -> dict[str, Any]:
    return {"count": 0, "by_source": {}, "last_query": "", "last_engine": ""}


def record_engine_search(
    task_id: str | None,
    source: str = "collector",
    query: str = "",
    engine: str = "",
) -> None:
    if not task_id:
        return
    src = (source or "collector").strip() or "collector"
    with _LOCK:
        row = _CALLS.setdefault(task_id, _empty())
        row["count"] = int(row.get("count") or 0) + 1
        by = dict(row.get("by_source") or {})
        by[src] = int(by.get(src) or 0) + 1
        row["by_source"] = by
        if query:
            row["last_query"] = str(query)[:300]
        if engine:
            row["last_engine"] = str(engine)
        _DIRTY.add(task_id)
        should_flush = row["count"] % 3 == 0
    if should_flush:
        persist_engine_usage(task_id)


def engine_snapshot(
    task_id: str | None,
    persisted: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not task_id:
        return _empty()
    with _LOCK:
        if task_id in _CALLS:
            return {
                "count": int(_CALLS[task_id].get("count") or 0),
                "by_source": dict(_CALLS[task_id].get("by_source") or {}),
                "last_query": _CALLS[task_id].get("last_query") or "",
                "last_engine": _CALLS[task_id].get("last_engine") or "",
            }
        if persisted and int(persisted.get("count") or 0):
            hydrated = {
                "count": int(persisted.get("count") or 0),
                "by_source": dict(persisted.get("by_source") or {}),
                "last_query": persisted.get("last_query") or "",
                "last_engine": persisted.get("last_engine") or "",
            }
            _CALLS[task_id] = dict(hydrated)
            return hydrated
    return _empty()


def persist_engine_usage(task_id: str | None) -> None:
    if not task_id:
        return
    with _LOCK:
        if task_id not in _DIRTY:
            return
        _DIRTY.discard(task_id)
    snap = engine_snapshot(task_id)
    if not snap.get("count"):
        return
    _write_runtime_stats(task_id, {"engine": snap})


def persist_dirty_engine_usage() -> None:
    with _LOCK:
        ids = list(_DIRTY)
    for task_id in ids:
        persist_engine_usage(task_id)
