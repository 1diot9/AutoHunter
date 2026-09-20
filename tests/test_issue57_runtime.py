"""Issue #57：扫完才算已检查、token/测绘用量落库后重启不丢。"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.engines import meter
from app.llm import usage


def host_is_checked(statuses: list[str]) -> bool:
    """与 app.api.tasks.host_is_checked 同口径：扫完且无待跑/待深挖。"""
    open_statuses = ("queued", "assigned", "scanning")
    finished = ("done", "dead")
    if any(s in open_statuses for s in statuses):
        return False
    return any(s in finished for s in statuses)


def test_host_is_checked_source_lock():
    text = (ROOT / "app/api/tasks.py").read_text(encoding="utf-8")
    assert "def host_is_checked" in text
    assert '_OPEN_STATUSES = ("queued", "assigned", "scanning")' in text
    assert '_FINISHED_STATUSES = ("done", "dead")' in text


def test_host_is_checked_finished_only():
    assert host_is_checked(["done"]) is True
    assert host_is_checked(["dead"]) is True
    assert host_is_checked(["done", "dead"]) is True


def test_host_is_checked_pending_deepen_does_not_count():
    assert host_is_checked(["done", "queued"]) is False
    assert host_is_checked(["dead", "assigned"]) is False
    assert host_is_checked(["done", "scanning"]) is False
    assert host_is_checked(["queued"]) is False
    assert host_is_checked(["scanning"]) is False


def test_host_is_checked_skip_only_does_not_count():
    assert host_is_checked(["skipped"]) is False
    assert host_is_checked(["skipped", "skipped"]) is False
    assert host_is_checked([]) is False


def test_usage_persists_and_hydrates(tmp_path, monkeypatch):
    db = tmp_path / "ah.db"
    sqlite3.connect(db).close()

    import app.db.session as session_mod
    monkeypatch.setattr(session_mod, "DB_PATH", str(db))

    usage.reset_usage_db_conn()
    usage._USAGE.clear()
    usage._FLUSHED.clear()
    usage._DIRTY.clear()
    usage.record_usage("t1", "demo-model", prompt_tokens=10, completion_tokens=5, total_tokens=15)
    usage.persist_usage("t1")

    usage_path = db.with_name("ah-usage.db")
    assert usage_path.is_file()
    row = sqlite3.connect(usage_path).execute(
        "SELECT prompt_tokens, completion_tokens, requests, model FROM token_usage_daily WHERE task_id='t1'"
    ).fetchone()
    assert row == (10, 5, 1, "demo-model")

    usage._USAGE.clear()
    usage._FLUSHED.clear()
    usage._DIRTY.clear()
    snap = usage.usage_snapshot("t1")
    assert snap["total_tokens"] == 15
    assert snap["requests"] == 1
    by_model = usage.usage_snapshot_by_model("t1")
    assert by_model[0]["model"] == "demo-model"


def test_engine_meter_persists_and_hydrates(tmp_path, monkeypatch):
    db = tmp_path / "ah.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY, runtime_stats TEXT)")
    con.execute("INSERT INTO tasks (id, runtime_stats) VALUES ('t1', '{}')")
    con.commit()
    con.close()

    import app.db.session as session_mod
    monkeypatch.setattr(session_mod, "DB_PATH", db)

    meter._CALLS.clear()
    meter._DIRTY.clear()
    meter.record_engine_search("t1", "collector", 'title="x"', "fofa")
    meter.record_engine_search("t1", "worker", 'host="a.example.edu.cn"', "fofa")
    meter.persist_engine_usage("t1")

    raw = sqlite3.connect(db).execute("SELECT runtime_stats FROM tasks WHERE id='t1'").fetchone()[0]
    saved = json.loads(raw)
    assert saved["engine"]["count"] == 2
    assert saved["engine"]["by_source"]["collector"] == 1
    assert saved["engine"]["by_source"]["worker"] == 1

    meter._CALLS.clear()
    meter._DIRTY.clear()
    snap = meter.engine_snapshot("t1", persisted=saved["engine"])
    assert snap["count"] == 2
    assert snap["last_engine"] == "fofa"


def test_token_usage_does_not_write_main_db(tmp_path, monkeypatch):
    main = tmp_path / "autohunter.db"
    sqlite3.connect(main).close()

    import app.db.session as session_mod
    monkeypatch.setattr(session_mod, "DB_PATH", str(main))
    usage.reset_usage_db_conn()
    usage._USAGE.clear()
    usage._FLUSHED.clear()
    usage._DIRTY.clear()
    usage._LAST_FLUSH = 0.0
    usage.record_usage("t1", "glm-5.3", prompt_tokens=20, completion_tokens=4, total_tokens=24)
    assert usage.flush_dirty_usage(force=True)

    main_tables = {
        r[0] for r in sqlite3.connect(main).execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert "token_usage_daily" not in main_tables
    usage_path = main.with_name("autohunter-usage.db")
    n = sqlite3.connect(usage_path).execute(
        "SELECT SUM(requests) FROM token_usage_daily"
    ).fetchone()[0]
    assert n == 1


def test_token_usage_migrates_from_main_db(tmp_path, monkeypatch):
    main = tmp_path / "autohunter.db"
    con = sqlite3.connect(main)
    con.execute("""
        CREATE TABLE token_usage_daily (
            date TEXT, task_id TEXT, model TEXT,
            prompt_tokens INTEGER, completion_tokens INTEGER,
            cache_hit_tokens INTEGER, cache_miss_tokens INTEGER, requests INTEGER
        )
    """)
    con.execute(
        "INSERT INTO token_usage_daily VALUES ('2026-09-18','t1','demo-model',100,20,10,90,3)"
    )
    con.commit()
    con.close()

    import app.db.session as session_mod
    monkeypatch.setattr(session_mod, "DB_PATH", str(main))
    usage.reset_usage_db_conn()
    usage._USAGE.clear()
    usage._FLUSHED.clear()
    usage._DIRTY.clear()
    snap = usage.usage_snapshot("t1")
    assert snap["prompt_tokens"] == 100
    assert snap["completion_tokens"] == 20
    assert snap["requests"] == 3
    rows = usage.query_usage_by_date("2026-09-18")
    assert rows and rows[0][5] == 3


def test_unflushed_delta_added_to_db_snapshot(tmp_path, monkeypatch):
    """SQLite 锁导致刷盘失败时，读路径仍要把内存增量叠到已落库数据上。"""
    db = tmp_path / "ah.db"
    sqlite3.connect(db).close()

    import app.db.session as session_mod
    monkeypatch.setattr(session_mod, "DB_PATH", str(db))

    usage.reset_usage_db_conn()
    usage._USAGE.clear()
    usage._FLUSHED.clear()
    usage._DIRTY.clear()
    usage._LAST_FLUSH = 0.0
    usage.record_usage("t1", "demo-model", prompt_tokens=100, completion_tokens=10, total_tokens=110)
    assert usage.flush_dirty_usage(force=True)

    monkeypatch.setattr(usage, "flush_dirty_usage", lambda **_kw: False)
    usage.record_usage("t1", "demo-model", prompt_tokens=50, completion_tokens=5, total_tokens=55)
    snap = usage.usage_snapshot("t1")
    assert snap["prompt_tokens"] == 150
    assert snap["completion_tokens"] == 15
    assert snap["requests"] == 2
    pending = usage.pending_deltas()
    assert pending and pending[0][2]["prompt_tokens"] == 50


def test_list_hosts_uses_light_columns():
    """hosts 聚合禁止 select(Target) 全实体（JSON 大字段会把大库租户事件循环打满）。"""
    text = (ROOT / "app/api/tasks.py").read_text(encoding="utf-8")
    hosts_fn = text.split("async def list_hosts", 1)[1].split("async def start_task", 1)[0]
    assert "select(Target).where(Target.task_id == task_id)" not in hosts_fn
    assert "Target.host" in hosts_fn
    assert "leaked_creds" not in hosts_fn


def test_queue_cluster_history_is_capped():
    text = (ROOT / "app/orchestrator.py").read_text(encoding="utf-8")
    assert "QUEUE_CLUSTER_HISTORY_LIMIT" in text
    assert 'Target.status.in_(["queued", "assigned", "scanning", "dead", "skipped"])' not in text
