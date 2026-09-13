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
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY, runtime_stats TEXT)")
    con.execute("INSERT INTO tasks (id, runtime_stats) VALUES ('t1', '{}')")
    con.commit()
    con.close()

    import app.db.session as session_mod
    monkeypatch.setattr(session_mod, "DB_PATH", db)

    usage._USAGE.clear()
    usage._DIRTY.clear()
    usage.record_usage("t1", "demo-model", prompt_tokens=10, completion_tokens=5, total_tokens=15)
    usage.persist_usage("t1")

    raw = sqlite3.connect(db).execute("SELECT runtime_stats FROM tasks WHERE id='t1'").fetchone()[0]
    saved = json.loads(raw)
    assert saved["llm"]["total_tokens"] == 15
    assert saved["llm"]["requests"] == 1
    assert saved["llm"]["model"] == "demo-model"

    usage._USAGE.clear()
    usage._DIRTY.clear()
    snap = usage.usage_snapshot("t1", persisted=saved["llm"])
    assert snap["total_tokens"] == 15
    assert snap["requests"] == 1


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
