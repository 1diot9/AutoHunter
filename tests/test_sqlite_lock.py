"""SQLite 写锁：worker 不应被打成异常退出。"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_is_sqlite_lock_error_detects_wrapped_autoflush():
    from app.db.session import is_sqlite_lock_error

    inner = Exception("database is locked")
    outer = Exception(
        "(raised as a result of Query-invoked autoflush; "
        "consider using a session.no_autoflush block if this flush is occurring prematurely) "
        "(sqlite3.OperationalError) database is locked"
    )
    outer.__cause__ = inner
    assert is_sqlite_lock_error(outer)
    assert is_sqlite_lock_error(Exception("sqlite3.OperationalError: database is locked"))
    assert not is_sqlite_lock_error(ValueError("other failure"))
    assert not is_sqlite_lock_error(None)


def test_commit_with_retry_retries_lock_then_succeeds():
    from app.db.session import commit_with_retry

    class FakeSession:
        def __init__(self):
            self.n = 0

        async def commit(self):
            self.n += 1
            if self.n < 3:
                raise Exception("database is locked")

    session = FakeSession()
    asyncio.run(commit_with_retry(session, attempts=5, base_delay=0.001))
    assert session.n == 3


def test_commit_with_retry_non_lock_raises_immediately():
    from app.db.session import commit_with_retry

    class FakeSession:
        async def commit(self):
            raise ValueError("boom")

    try:
        asyncio.run(commit_with_retry(FakeSession(), attempts=5, base_delay=0.001))
    except ValueError as e:
        assert "boom" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_lock_is_transient_worker_error():
    from app.orchestrator import TaskRunner

    assert TaskRunner._is_transient_worker_error(
        "OperationalError: (raised as a result of Query-invoked autoflush) "
        "(sqlite3.OperationalError) database is locked"
    )
    assert not TaskRunner._is_transient_worker_error("API Key 无效")


def test_worker_commits_scanning_before_history_queries():
    text = (ROOT / "app" / "orchestrator.py").read_text(encoding="utf-8")
    setup = text.split("async def _run_worker_inner", 1)[1].split(
        "async def _persist_worker_result", 1
    )[0]
    commit_pos = setup.find("await commit_with_retry(session)")
    hist_pos = setup.find("_build_duplicate_history")
    intel_pos = setup.find("lookup_intel")
    assert commit_pos >= 0
    assert hist_pos > commit_pos
    assert intel_pos > commit_pos
    assert "worker 异常退出" in text
    assert "_requeue_after_sqlite_lock" in text
    crash = text.split("async def _run_worker(", 1)[1].split(
        "async def _run_worker_inner", 1
    )[0]
    assert "is_sqlite_lock_error" in crash
    assert crash.find("_requeue_after_sqlite_lock") < crash.find("worker 异常退出")


def test_orchestrator_uses_sync_no_autoflush():
    """AsyncSession.no_autoflush 是同步 CM；async with 会把 worker 打成异常退出。"""
    text = (ROOT / "app" / "orchestrator.py").read_text(encoding="utf-8")
    assert "async with session.no_autoflush" not in text
    assert "with session.no_autoflush:" in text


def test_async_session_no_autoflush_rejects_async_with():
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    async def run():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sl = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with sl() as session:
                with session.no_autoflush:
                    assert session.autoflush is False
                assert session.autoflush is True
                try:
                    async with session.no_autoflush:
                        pass
                except TypeError as e:
                    assert "asynchronous context manager" in str(e)
                else:
                    raise AssertionError("expected TypeError from async with no_autoflush")
        finally:
            await engine.dispose()

    asyncio.run(run())
