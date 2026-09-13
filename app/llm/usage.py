"""任务级 LLM token 用量计数。

运行态走内存，便于看板实时刷新；同时写入 tasks.runtime_stats，
任务结束或进程重启后仍能看到累计消耗。
"""
from __future__ import annotations

import json
import sqlite3
from threading import Lock
from time import time
from typing import Any

_LOCK = Lock()
_WRITE_LOCK = Lock()
_USAGE: dict[str, dict[str, Any]] = {}
_DIRTY: set[str] = set()


def _empty(model: str = "") -> dict[str, Any]:
    return {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cache_hit_tokens": 0,
        "cache_miss_tokens": 0,
        "requests": 0,
        "model": model,
        "updated_at": None,
    }


def _normalize(row: dict[str, Any] | None, model: str = "") -> dict[str, Any]:
    out = _empty(model)
    if not row:
        return out
    for key in (
        "prompt_tokens", "completion_tokens", "total_tokens",
        "cache_hit_tokens", "cache_miss_tokens", "requests",
    ):
        try:
            out[key] = max(0, int(row.get(key) or 0))
        except (TypeError, ValueError):
            pass
    if row.get("model"):
        out["model"] = str(row.get("model") or model)
    elif model:
        out["model"] = model
    out["updated_at"] = row.get("updated_at")
    return out


def record_usage(task_id: str | None, model: str, prompt_tokens: int = 0,
                 completion_tokens: int = 0, total_tokens: int = 0,
                 cache_hit_tokens: int = 0, cache_miss_tokens: int = 0) -> None:
    if not task_id:
        return
    prompt = max(0, int(prompt_tokens or 0))
    completion = max(0, int(completion_tokens or 0))
    total = max(0, int(total_tokens or 0)) or (prompt + completion)
    cache_hit = max(0, int(cache_hit_tokens or 0))
    cache_miss = max(0, int(cache_miss_tokens or 0))
    should_flush = False
    with _LOCK:
        row = _USAGE.setdefault(task_id, _empty(model))
        row["prompt_tokens"] += prompt
        row["completion_tokens"] += completion
        row["total_tokens"] += total
        row["cache_hit_tokens"] = row.get("cache_hit_tokens", 0) + cache_hit
        row["cache_miss_tokens"] = row.get("cache_miss_tokens", 0) + cache_miss
        row["requests"] += 1
        row["model"] = model
        row["updated_at"] = time()
        _DIRTY.add(task_id)
        should_flush = row["requests"] % 5 == 0
    if should_flush:
        persist_usage(task_id)


def usage_snapshot(task_id: str | None, model: str = "",
                   persisted: dict[str, Any] | None = None) -> dict[str, Any]:
    if not task_id:
        return _empty(model)
    with _LOCK:
        if task_id in _USAGE:
            row = dict(_USAGE[task_id])
            if model and not row.get("model"):
                row["model"] = model
            return row
        if persisted and (
            persisted.get("requests") or persisted.get("total_tokens")
            or persisted.get("prompt_tokens")
        ):
            hydrated = _normalize(persisted, model)
            _USAGE[task_id] = dict(hydrated)
            return hydrated
    return _empty(model)


def persist_usage(task_id: str | None) -> None:
    """把内存用量合并进 tasks.runtime_stats。缺列时静默跳过。"""
    if not task_id:
        return
    with _LOCK:
        if task_id not in _DIRTY:
            return
        row = dict(_USAGE.get(task_id) or {})
        _DIRTY.discard(task_id)
    if not row or not (row.get("requests") or row.get("total_tokens")):
        return
    _write_runtime_stats(task_id, {"llm": _normalize(row, str(row.get("model") or ""))})


def persist_dirty_usage() -> None:
    with _LOCK:
        ids = list(_DIRTY)
    for task_id in ids:
        persist_usage(task_id)


def _write_runtime_stats(task_id: str, patch: dict[str, Any]) -> None:
    try:
        from app.db.session import DB_PATH
    except Exception:
        return
    with _WRITE_LOCK:
        try:
            con = sqlite3.connect(DB_PATH, timeout=5)
            try:
                cols = {r[1] for r in con.execute("PRAGMA table_info(tasks)")}
                if "runtime_stats" not in cols:
                    return
                raw = con.execute(
                    "SELECT runtime_stats FROM tasks WHERE id = ?", (task_id,)
                ).fetchone()
                if not raw:
                    return
                current: dict[str, Any] = {}
                if raw[0]:
                    try:
                        current = json.loads(raw[0]) if isinstance(raw[0], str) else dict(raw[0] or {})
                    except (TypeError, ValueError, json.JSONDecodeError):
                        current = {}
                current.update(patch)
                con.execute(
                    "UPDATE tasks SET runtime_stats = ? WHERE id = ?",
                    (json.dumps(current, ensure_ascii=False), task_id),
                )
                con.commit()
            finally:
                con.close()
        except Exception:
            return
