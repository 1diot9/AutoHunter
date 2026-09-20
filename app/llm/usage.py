"""任务级 LLM token 用量计数（内存实时 + 独立库持久化）。

内存计数支撑看板实时观察；落盘按天聚合（CST 日期 + 任务 + 模型维度），
进程重启不丢数据，支持历史日历与成本统计。

设计要点：
- 内存按 (task_id, model) 维度累积，不再只记最后一个模型
- 计量库与主库拆开（默认 autohunter-usage.db），写入不再和 worker/事件抢同一把 SQLite 写锁
- 增量先记内存，后台/批量 upsert；读路径把未落库增量叠到 DB 上
- 成本不预存——查询时按 pricing 配置实时计算，用户改单价后历史自动重算
- usage_snapshot(task_id) 向后兼容：聚合所有模型返回汇总
- usage_snapshot_by_model(task_id) 返回按模型拆分明细
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock, Thread
from time import sleep, time
from typing import Any

logger = logging.getLogger("autohunter.llm.usage")

CST = timezone(timedelta(hours=8))

_COUNTER_KEYS = (
    "prompt_tokens", "completion_tokens", "total_tokens",
    "cache_hit_tokens", "cache_miss_tokens", "requests",
)

# 内存计数：{(task_id, model): {prompt_tokens, completion_tokens, ...}}
_USAGE_LOCK = Lock()
_USAGE: dict[tuple[str, str], dict[str, Any]] = {}
# 本进程已成功写入 DB 的累计值（与 _USAGE 同维度）。差值 = 未落库增量。
_FLUSHED: dict[tuple[str, str], dict[str, int]] = {}
_DIRTY: set[tuple[str, str]] = set()

# 计量库：独立 SQLite 文件 + 同步连接，不碰主库写锁
_DB_LOCK = Lock()
_DB_CONN: sqlite3.Connection | None = None
_DB_PATH_USED: str | None = None
_FLUSHER_LOCK = Lock()
_FLUSHER: Thread | None = None
_LAST_FLUSH = 0.0
_FLUSH_INTERVAL = 1.0

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


def usage_db_path() -> str:
    """Token 计量库路径：USAGE_DB_PATH，或主库同目录的 `<stem>-usage.db`。"""
    env = (os.environ.get("USAGE_DB_PATH") or "").strip()
    if env:
        return env
    try:
        from app.db.session import DB_PATH
        main = Path(DB_PATH)
    except Exception:
        main = Path("data") / "autohunter.db"
    return str(main.with_name(f"{main.stem}-usage.db"))


def reset_usage_db_conn() -> None:
    """测试/切换路径时关掉缓存连接。"""
    global _DB_CONN, _DB_PATH_USED
    with _DB_LOCK:
        if _DB_CONN is not None:
            try:
                _DB_CONN.close()
            except Exception:
                pass
            _DB_CONN = None
        _DB_PATH_USED = None


def _migrate_from_main_db(conn: sqlite3.Connection) -> None:
    """主库里若还有 token_usage_daily，且计量库为空，则拷过来一次。"""
    try:
        count = conn.execute("SELECT COUNT(*) FROM token_usage_daily").fetchone()[0]
        if count:
            return
        from app.db.session import DB_PATH
        main = Path(DB_PATH)
        usage = Path(usage_db_path())
        if not main.is_file():
            return
        try:
            if main.resolve() == usage.resolve():
                return
        except OSError:
            if str(main) == str(usage):
                return
        src = sqlite3.connect(str(main), timeout=5)
        try:
            tables = {
                r[0] for r in src.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "token_usage_daily" not in tables:
                return
            rows = src.execute(
                "SELECT date, task_id, model, prompt_tokens, completion_tokens, "
                "cache_hit_tokens, cache_miss_tokens, requests FROM token_usage_daily"
            ).fetchall()
        finally:
            src.close()
        if not rows:
            return
        conn.executemany(
            "INSERT OR IGNORE INTO token_usage_daily "
            "(date, task_id, model, prompt_tokens, completion_tokens, "
            "cache_hit_tokens, cache_miss_tokens, requests) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        logger.info("已从主库迁移 %d 条 token 用量到独立计量库", len(rows))
    except Exception as e:
        logger.warning("token 用量从主库迁移跳过: %s", e)


def _get_db_conn() -> sqlite3.Connection | None:
    """获取（惰性创建）计量库连接。失败时返回 None，不影响内存计数。"""
    global _DB_CONN, _DB_PATH_USED
    path = usage_db_path()
    if _DB_CONN is not None and _DB_PATH_USED == path:
        return _DB_CONN
    with _DB_LOCK:
        if _DB_CONN is not None and _DB_PATH_USED == path:
            return _DB_CONN
        if _DB_CONN is not None:
            try:
                _DB_CONN.close()
            except Exception:
                pass
            _DB_CONN = None
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA synchronous=NORMAL")
            for stmt in _DDL.split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(stmt)
            conn.commit()
            _migrate_from_main_db(conn)
            _DB_CONN = conn
            _DB_PATH_USED = path
            logger.info("token 计量库已连接: %s", path)
        except Exception as e:
            logger.warning("token 计量库连接失败（内存计数不受影响）: %s", e)
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


def _zero_counters() -> dict[str, int]:
    return {k: 0 for k in _COUNTER_KEYS}


def _row_counters(row: dict[str, Any]) -> dict[str, int]:
    out = _zero_counters()
    for key in _COUNTER_KEYS:
        try:
            out[key] = max(0, int(row.get(key) or 0))
        except (TypeError, ValueError):
            out[key] = 0
    if not out["total_tokens"]:
        out["total_tokens"] = out["prompt_tokens"] + out["completion_tokens"]
    return out


def _counter_delta(current: dict[str, int], flushed: dict[str, int] | None) -> dict[str, int]:
    prev = flushed or _zero_counters()
    return {k: max(0, int(current.get(k, 0) or 0) - int(prev.get(k, 0) or 0)) for k in _COUNTER_KEYS}


def _has_usage(counters: dict[str, int]) -> bool:
    return bool(
        counters.get("requests")
        or counters.get("prompt_tokens")
        or counters.get("completion_tokens")
        or counters.get("total_tokens")
    )


def _add_counters(dst: dict[str, Any], src: dict[str, int]) -> dict[str, Any]:
    for key in _COUNTER_KEYS:
        dst[key] = int(dst.get(key) or 0) + int(src.get(key) or 0)
    dst["total_tokens"] = int(dst.get("prompt_tokens") or 0) + int(dst.get("completion_tokens") or 0)
    return dst


def pending_deltas() -> list[tuple[str, str, dict[str, int]]]:
    """本进程尚未写入 token_usage_daily 的增量 [(task_id, model, counters), ...]。"""
    with _USAGE_LOCK:
        out: list[tuple[str, str, dict[str, int]]] = []
        for key, row in _USAGE.items():
            delta = _counter_delta(_row_counters(row), _FLUSHED.get(key))
            if _has_usage(delta):
                out.append((key[0], key[1], delta))
        return out


def _ensure_flusher() -> None:
    global _FLUSHER
    with _FLUSHER_LOCK:
        if _FLUSHER is not None and _FLUSHER.is_alive():
            return
        t = Thread(target=_flush_loop, name="token-usage-flush", daemon=True)
        _FLUSHER = t
        t.start()


def _flush_loop() -> None:
    while True:
        sleep(2.0)
        try:
            flush_dirty_usage(force=True)
        except Exception as e:
            logger.warning("token_usage 后台刷盘失败: %s", e)


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
        _DIRTY.add(key)

    _ensure_flusher()
    flush_dirty_usage(force=False)


def flush_dirty_usage(*, force: bool = False) -> bool:
    """把未落库增量一次性 upsert。force 时多等锁；否则短超时，失败留待下次。"""
    global _LAST_FLUSH
    now = time()
    # 首写立刻落盘（方便测试）；之后 1s 内合并，避免和事件循环抢 SQLite 写锁
    if not force and _LAST_FLUSH and now - _LAST_FLUSH < _FLUSH_INTERVAL:
        return True

    with _USAGE_LOCK:
        items: list[tuple[tuple[str, str], dict[str, int]]] = []
        keys = list(_DIRTY) if _DIRTY else list(_USAGE.keys())
        for key in keys:
            row = _USAGE.get(key)
            if not row:
                _DIRTY.discard(key)
                continue
            delta = _counter_delta(_row_counters(row), _FLUSHED.get(key))
            if _has_usage(delta):
                items.append((key, delta))
            else:
                _DIRTY.discard(key)
    if not items:
        _LAST_FLUSH = now
        return True

    conn = _get_db_conn()
    if conn is None:
        return False

    today = _today_cst()
    busy_ms = 5000 if force else 200
    attempts = 4 if force else 2
    last_err: Exception | None = None
    for attempt in range(attempts):
        try:
            with _DB_LOCK:
                conn.execute(f"PRAGMA busy_timeout={busy_ms}")
                for (task_id, model), delta in items:
                    conn.execute(_UPSERT_SQL, (
                        today, task_id, model,
                        delta["prompt_tokens"], delta["completion_tokens"],
                        delta["cache_hit_tokens"], delta["cache_miss_tokens"],
                        delta["requests"],
                    ))
                conn.commit()
            with _USAGE_LOCK:
                for key, delta in items:
                    prev = _FLUSHED.get(key) or _zero_counters()
                    _FLUSHED[key] = {k: int(prev.get(k, 0)) + int(delta.get(k, 0)) for k in _COUNTER_KEYS}
                    # 刷盘期间新进的增量仍留在 _USAGE - _FLUSHED
                    cur = _USAGE.get(key)
                    if cur and not _has_usage(_counter_delta(_row_counters(cur), _FLUSHED[key])):
                        _DIRTY.discard(key)
                    else:
                        _DIRTY.add(key)
            _LAST_FLUSH = time()
            return True
        except sqlite3.OperationalError as e:
            last_err = e
            msg = str(e).lower()
            if "locked" not in msg and "busy" not in msg:
                break
            sleep(0.05 * (attempt + 1))
        except Exception as e:
            last_err = e
            break
    logger.warning("token_usage DB 写入失败（内存计数不受影响，将重试）: %s", last_err)
    return False


def _merge_pending_into_models(task_id: str, models: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_model = {str(m.get("model") or ""): dict(m) for m in models}
    for tid, mdl, delta in pending_deltas():
        if tid != task_id:
            continue
        row = by_model.get(mdl)
        if row is None:
            row = apply_cache_reconcile({
                "model": mdl,
                **_zero_counters(),
                "updated_at": time(),
            })
        _add_counters(row, delta)
        row["updated_at"] = time()
        by_model[mdl] = apply_cache_reconcile(row)
    return list(by_model.values())


def usage_snapshot(task_id: str | None, model: str = "",
                   persisted: dict[str, Any] | None = None) -> dict[str, Any]:
    """聚合所有模型的用量汇总（DB + 本进程未落库增量）。"""
    if not task_id:
        return _empty(model)
    agg = _empty(model)
    found = False
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
                agg = {
                    "prompt_tokens": pt or 0,
                    "completion_tokens": ct or 0,
                    "total_tokens": (pt or 0) + (ct or 0),
                    "cache_hit_tokens": cht or 0,
                    "cache_miss_tokens": cmt or 0,
                    "requests": req or 0,
                    "model": model,
                    "updated_at": time(),
                }
                found = True
        except Exception as e:
            logger.debug("usage_snapshot DB 读取失败，回退内存: %s", e)
    if not found:
        with _USAGE_LOCK:
            rows = [dict(v) for k, v in _USAGE.items() if k[0] == task_id]
        last_model = ""
        latest_ts: float | None = None
        for r in rows:
            _add_counters(agg, _row_counters(r))
            ts = r.get("updated_at")
            if ts and (latest_ts is None or ts > latest_ts):
                latest_ts = ts
                last_model = r.get("model", "")
            found = True
        agg["model"] = model or last_model or agg["model"]
        agg["updated_at"] = latest_ts
    else:
        for tid, mdl, delta in pending_deltas():
            if tid == task_id:
                _add_counters(agg, delta)
                agg["model"] = model or mdl or agg["model"]
                agg["updated_at"] = time()
        if not agg.get("model"):
            with _USAGE_LOCK:
                latest_ts: float | None = None
                last_model = ""
                for k, r in _USAGE.items():
                    if k[0] != task_id:
                        continue
                    ts = r.get("updated_at")
                    if ts and (latest_ts is None or ts > latest_ts):
                        latest_ts = ts
                        last_model = r.get("model") or k[1]
                agg["model"] = model or last_model or agg["model"]
    if found and (agg.get("requests") or agg.get("total_tokens")):
        return apply_cache_reconcile(agg)
    if persisted and (persisted.get("requests") or persisted.get("total_tokens") or persisted.get("prompt_tokens")):
        out = _empty(model)
        for key in _COUNTER_KEYS:
            try:
                out[key] = max(0, int(persisted.get(key) or 0))
            except (TypeError, ValueError):
                pass
        if persisted.get("model"):
            out["model"] = str(persisted.get("model") or model)
        out["updated_at"] = persisted.get("updated_at")
        for tid, mdl, delta in pending_deltas():
            if tid == task_id:
                _add_counters(out, delta)
        return apply_cache_reconcile(out)
    return apply_cache_reconcile(agg)


def usage_snapshot_by_model(task_id: str | None) -> list[dict[str, Any]]:
    """返回按模型拆分的用量明细列表（DB + 未落库增量）。"""
    if not task_id:
        return []
    result: list[dict[str, Any]] = []
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
        except Exception as e:
            logger.debug("usage_snapshot_by_model DB 读取失败，回退内存: %s", e)
    if not result:
        with _USAGE_LOCK:
            result = [apply_cache_reconcile(dict(v)) for k, v in _USAGE.items() if k[0] == task_id]
        return result
    return _merge_pending_into_models(task_id, result)


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
        except Exception as e:
            logger.debug("usage_by_task_model DB 读取失败，回退内存: %s", e)
    if not out:
        with _USAGE_LOCK:
            for (tid, _mdl), v in _USAGE.items():
                out.setdefault(tid, []).append(apply_cache_reconcile(dict(v)))
        return out
    pending_by_task: dict[str, list[dict[str, Any]]] = {}
    for tid, mdl, delta in pending_deltas():
        pending_by_task.setdefault(tid, []).append({"model": mdl, **delta})
    for tid, extras in pending_by_task.items():
        merged = {str(m.get("model") or ""): dict(m) for m in out.get(tid, [])}
        for extra in extras:
            mdl = str(extra.get("model") or "")
            row = merged.get(mdl)
            if row is None:
                row = apply_cache_reconcile({
                    "model": mdl,
                    **_zero_counters(),
                    "updated_at": time(),
                })
            _add_counters(row, extra)
            row["updated_at"] = time()
            merged[mdl] = apply_cache_reconcile(row)
        out[tid] = list(merged.values())
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


def persist_usage(task_id: str | None, *, force: bool = True) -> None:
    """把未落盘增量刷进独立计量库。不再写主库 tasks.runtime_stats。"""
    if not task_id:
        return
    flush_dirty_usage(force=force)


def query_usage_by_date(date: str) -> list[tuple[Any, ...]]:
    """日历日按模型聚合：[(model, prompt, completion, cache_hit, cache_miss, requests), ...]。"""
    conn = _get_db_conn()
    if conn is None:
        return []
    try:
        with _DB_LOCK:
            return conn.execute(
                "SELECT model, SUM(prompt_tokens), SUM(completion_tokens), "
                "SUM(cache_hit_tokens), SUM(cache_miss_tokens), SUM(requests) "
                "FROM token_usage_daily WHERE date = ? GROUP BY model",
                (date,),
            ).fetchall()
    except Exception as e:
        logger.debug("query_usage_by_date 失败: %s", e)
        return []


def query_usage_date_range(start: str, end: str) -> list[tuple[Any, ...]]:
    """[start, end) CST 日期行：[(date, model, prompt, completion, cache_hit), ...]。"""
    conn = _get_db_conn()
    if conn is None:
        return []
    try:
        with _DB_LOCK:
            return conn.execute(
                "SELECT date, model, prompt_tokens, completion_tokens, cache_hit_tokens "
                "FROM token_usage_daily WHERE date >= ? AND date < ?",
                (start, end),
            ).fetchall()
    except Exception as e:
        logger.debug("query_usage_date_range 失败: %s", e)
        return []


def persist_dirty_usage() -> None:
    flush_dirty_usage(force=True)


def _write_runtime_stats(task_id: str, patch: dict[str, Any]) -> None:
    try:
        from app.db.session import DB_PATH
    except Exception:
        return
    try:
        con = sqlite3.connect(DB_PATH, timeout=30)
        try:
            con.execute("PRAGMA busy_timeout=30000")
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
