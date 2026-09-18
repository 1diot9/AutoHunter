"""任务级 LLM token 用量计数（内存实时 + DB 持久化）。

内存计数支撑看板实时观察；DB 持久化按天聚合（CST 日期 + 任务 + 模型维度），
进程重启不丢数据，支持历史日历与成本统计。

设计要点：
- 内存按 (task_id, model) 维度累积，不再只记最后一个模型
- 每次 record_usage 同步增量 upsert 到 DB（SQLite WAL 下开销极小）
- 成本不预存——查询时按 pricing 配置实时计算，用户改单价后历史自动重算
- usage_snapshot(task_id) 向后兼容：聚合所有模型返回汇总
- usage_snapshot_by_model(task_id) 返回按模型拆分明细
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from threading import Lock
from time import time
from typing import Any

logger = logging.getLogger("autohunter.llm.usage")

CST = timezone(timedelta(hours=8))

# 内存计数：{(task_id, model): {prompt_tokens, completion_tokens, ...}}
_USAGE_LOCK = Lock()
_USAGE: dict[tuple[str, str], dict[str, Any]] = {}

# DB 持久化：独立的同步连接（与异步引擎共用同一 SQLite 文件，WAL 模式并发安全）
_DB_LOCK = Lock()
_DB_CONN: sqlite3.Connection | None = None

_DDL = """
CREATE TABLE IF NOT EXISTS token_usage_daily (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date VARCHAR(10) NOT NULL,
    task_id VARCHAR(32) NOT NULL,
    model VARCHAR(100) DEFAULT '',
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    cache_hit_tokens INTEGER DEFAULT 0,
    cache_miss_tokens INTEGER DEFAULT 0,
    requests INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_token_usage_daily ON token_usage_daily(date, task_id, model);
CREATE INDEX IF NOT EXISTS ix_token_usage_daily_date ON token_usage_daily(date);
CREATE INDEX IF NOT EXISTS ix_token_usage_daily_task ON token_usage_daily(task_id);
"""

_UPSERT_SQL = """
INSERT INTO token_usage_daily (date, task_id, model, prompt_tokens, completion_tokens, cache_hit_tokens, cache_miss_tokens, requests)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(date, task_id, model) DO UPDATE SET
    prompt_tokens = token_usage_daily.prompt_tokens + excluded.prompt_tokens,
    completion_tokens = token_usage_daily.completion_tokens + excluded.completion_tokens,
    cache_hit_tokens = token_usage_daily.cache_hit_tokens + excluded.cache_hit_tokens,
    cache_miss_tokens = token_usage_daily.cache_miss_tokens + excluded.cache_miss_tokens,
    requests = token_usage_daily.requests + excluded.requests
"""


def _get_db_conn() -> sqlite3.Connection | None:
    """获取（惰性创建）同步 DB 连接。失败时返回 None，不影响内存计数。"""
    global _DB_CONN
    if _DB_CONN is not None:
        return _DB_CONN
    with _DB_LOCK:
        if _DB_CONN is not None:
            return _DB_CONN
        try:
            from app.db.session import DB_PATH
            conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA synchronous=NORMAL")
            for stmt in _DDL.split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(stmt)
            conn.commit()
            _DB_CONN = conn
            logger.info("token_usage_daily DB 连接已建立")
        except Exception as e:
            logger.warning("token_usage_daily DB 连接失败（内存计数不受影响）: %s", e)
            return None
    return _DB_CONN


def _today_cst() -> str:
    """返回当前 CST 日期字符串 YYYY-MM-DD。"""
    return datetime.now(CST).strftime("%Y-%m-%d")


def reconcile_cache_tokens(
    prompt_tokens: int,
    cache_hit: int,
    cache_miss: int = 0,
    *,
    cache_reported: bool = False,
) -> tuple[int, int]:
    """把缓存命中/未命中对齐到 prompt_tokens。

    命中率必须用 hit / prompt。很多网关只回 cached_tokens，不回 miss；
    Anthropic 的 cache_creation 是写缓存，也不是未命中。有命中字段或明确
    报过缓存时，未命中 = prompt - hit。
    """
    prompt = max(0, int(prompt_tokens or 0))
    hit = max(0, int(cache_hit or 0))
    miss = max(0, int(cache_miss or 0))
    if prompt:
        hit = min(hit, prompt)
        if hit > 0 or cache_reported:
            miss = prompt - hit
        elif miss > prompt:
            miss = prompt
    return hit, miss


def apply_cache_reconcile(row: dict[str, Any]) -> dict[str, Any]:
    """就地补全一行用量里缺的 miss，供读旧数据时修正虚假 100% 命中率。"""
    hit, miss = reconcile_cache_tokens(
        row.get("prompt_tokens", 0),
        row.get("cache_hit_tokens", 0),
        row.get("cache_miss_tokens", 0),
    )
    row["cache_hit_tokens"] = hit
    row["cache_miss_tokens"] = miss
    return row


def record_usage(task_id: str | None, model: str, prompt_tokens: int = 0,
                 completion_tokens: int = 0, total_tokens: int = 0,
                 cache_hit_tokens: int = 0, cache_miss_tokens: int = 0) -> None:
    if not task_id:
        return
    prompt = max(0, int(prompt_tokens or 0))
    completion = max(0, int(completion_tokens or 0))
    total = max(0, int(total_tokens or 0)) or (prompt + completion)
    cache_hit, cache_miss = reconcile_cache_tokens(
        prompt, cache_hit_tokens, cache_miss_tokens,
        cache_reported=bool(cache_hit_tokens or cache_miss_tokens),
    )

    # 1) 内存更新（快速，向后兼容看板轮询）
    key = (task_id, model)
    with _USAGE_LOCK:
        row = _USAGE.get(key)
        if row is None:
            row = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "cache_hit_tokens": 0,
                "cache_miss_tokens": 0,
                "requests": 0,
                "model": model,
                "updated_at": None,
            }
            _USAGE[key] = row
        row["prompt_tokens"] += prompt
        row["completion_tokens"] += completion
        row["total_tokens"] += total
        row["cache_hit_tokens"] = row.get("cache_hit_tokens", 0) + cache_hit
        row["cache_miss_tokens"] = row.get("cache_miss_tokens", 0) + cache_miss
        row["requests"] += 1
        row["updated_at"] = time()

    # 2) DB 增量持久化（每次调用 upsert 增量，进程重启不丢）
    try:
        conn = _get_db_conn()
        if conn is not None:
            today = _today_cst()
            with _DB_LOCK:
                conn.execute(_UPSERT_SQL, (
                    today, task_id, model,
                    prompt, completion, cache_hit, cache_miss, 1,
                ))
                conn.commit()
    except Exception as e:
        logger.debug("token_usage DB 写入失败（内存计数不受影响）: %s", e)


def usage_snapshot(task_id: str | None, model: str = "",
                   persisted: dict[str, Any] | None = None) -> dict[str, Any]:
    """聚合所有模型的用量汇总（从 DB 读取，重启不丢）。"""
    if not task_id:
        return _empty(model)
    # 优先从 DB 读取（持久化，重启不丢）
    conn = _get_db_conn()
    if conn is not None:
        try:
            with _DB_LOCK:
                row = conn.execute(
                    "SELECT SUM(prompt_tokens), SUM(completion_tokens), "
                    "SUM(cache_hit_tokens), SUM(cache_miss_tokens), SUM(requests) "
                    "FROM token_usage_daily WHERE task_id = ?",
                    (task_id,)
                ).fetchone()
            if row and row[0] is not None:
                pt, ct, cht, cmt, req = row
                return apply_cache_reconcile({
                    "prompt_tokens": pt or 0,
                    "completion_tokens": ct or 0,
                    "total_tokens": (pt or 0) + (ct or 0),
                    "cache_hit_tokens": cht or 0,
                    "cache_miss_tokens": cmt or 0,
                    "requests": req or 0,
                    "model": model,
                    "updated_at": time(),
                })
        except Exception as e:
            logger.debug("usage_snapshot DB 读取失败，回退内存: %s", e)
    # 回退到内存
    with _USAGE_LOCK:
        rows = [dict(v) for k, v in _USAGE.items() if k[0] == task_id]
    if not rows:
        return _empty(model)
    agg = _empty(model)
    last_model = ""
    latest_ts: float | None = None
    for r in rows:
        agg["prompt_tokens"] += r.get("prompt_tokens", 0)
        agg["completion_tokens"] += r.get("completion_tokens", 0)
        agg["total_tokens"] += r.get("total_tokens", 0)
        agg["cache_hit_tokens"] += r.get("cache_hit_tokens", 0)
        agg["cache_miss_tokens"] += r.get("cache_miss_tokens", 0)
        agg["requests"] += r.get("requests", 0)
        ts = r.get("updated_at")
        if ts and (latest_ts is None or ts > latest_ts):
            latest_ts = ts
            last_model = r.get("model", "")
    agg["model"] = model or last_model or agg["model"]
    agg["updated_at"] = latest_ts
    if agg["requests"] or agg["total_tokens"]:
        return apply_cache_reconcile(agg)
    if persisted and (persisted.get("requests") or persisted.get("total_tokens") or persisted.get("prompt_tokens")):
        out = _empty(model)
        for key in ("prompt_tokens", "completion_tokens", "total_tokens",
                    "cache_hit_tokens", "cache_miss_tokens", "requests"):
            try:
                out[key] = max(0, int(persisted.get(key) or 0))
            except (TypeError, ValueError):
                pass
        if persisted.get("model"):
            out["model"] = str(persisted.get("model") or model)
        out["updated_at"] = persisted.get("updated_at")
        return apply_cache_reconcile(out)
    return apply_cache_reconcile(agg)


def usage_snapshot_by_model(task_id: str | None) -> list[dict[str, Any]]:
    """返回按模型拆分的用量明细列表（从 DB 读取，重启不丢）。"""
    if not task_id:
        return []
    # 优先从 DB 读取
    conn = _get_db_conn()
    if conn is not None:
        try:
            with _DB_LOCK:
                rows = conn.execute(
                    "SELECT model, SUM(prompt_tokens), SUM(completion_tokens), "
                    "SUM(cache_hit_tokens), SUM(cache_miss_tokens), SUM(requests) "
                    "FROM token_usage_daily WHERE task_id = ? GROUP BY model",
                    (task_id,)
                ).fetchall()
            if rows:
                result = []
                for row in rows:
                    mdl, pt, ct, cht, cmt, req = row
                    result.append(apply_cache_reconcile({
                        "model": mdl or "",
                        "prompt_tokens": pt or 0,
                        "completion_tokens": ct or 0,
                        "total_tokens": (pt or 0) + (ct or 0),
                        "cache_hit_tokens": cht or 0,
                        "cache_miss_tokens": cmt or 0,
                        "requests": req or 0,
                        "updated_at": time(),
                    }))
                return result
        except Exception as e:
            logger.debug("usage_snapshot_by_model DB 读取失败，回退内存: %s", e)
    # 回退到内存
    with _USAGE_LOCK:
        return [apply_cache_reconcile(dict(v)) for k, v in _USAGE.items() if k[0] == task_id]


def usage_by_task_model() -> dict[str, list[dict[str, Any]]]:
    """一次扫表：所有任务按模型聚合的用量（供任务列表批量算成本）。

    返回 {task_id: [{model, prompt_tokens, ...}, ...]}。
    """
    out: dict[str, list[dict[str, Any]]] = {}
    conn = _get_db_conn()
    if conn is not None:
        try:
            with _DB_LOCK:
                rows = conn.execute(
                    "SELECT task_id, model, SUM(prompt_tokens), SUM(completion_tokens), "
                    "SUM(cache_hit_tokens), SUM(cache_miss_tokens), SUM(requests) "
                    "FROM token_usage_daily GROUP BY task_id, model"
                ).fetchall()
            for row in rows:
                tid, mdl, pt, ct, cht, cmt, req = row
                if not tid:
                    continue
                out.setdefault(tid, []).append(apply_cache_reconcile({
                    "model": mdl or "",
                    "prompt_tokens": pt or 0,
                    "completion_tokens": ct or 0,
                    "total_tokens": (pt or 0) + (ct or 0),
                    "cache_hit_tokens": cht or 0,
                    "cache_miss_tokens": cmt or 0,
                    "requests": req or 0,
                    "updated_at": time(),
                }))
            if out:
                return out
        except Exception as e:
            logger.debug("usage_by_task_model DB 读取失败，回退内存: %s", e)
    with _USAGE_LOCK:
        for (tid, _mdl), v in _USAGE.items():
            out.setdefault(tid, []).append(apply_cache_reconcile(dict(v)))
    return out


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


def persist_usage(task_id: str | None) -> None:
    """把日历/内存用量同步进 tasks.runtime_stats，供任务结束后看板回看。"""
    if not task_id:
        return
    snap = usage_snapshot(task_id)
    if not snap.get("requests") and not snap.get("total_tokens"):
        return
    _write_runtime_stats(task_id, {"llm": snap})


def persist_dirty_usage() -> None:
    """日历路径每次 record_usage 已落库；这里无需额外脏集合。"""
    return


def _write_runtime_stats(task_id: str, patch: dict[str, Any]) -> None:
    try:
        from app.db.session import DB_PATH
    except Exception:
        return
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
