"""活动流分页 + 看板默认不带事件。

运行：
  python -m unittest tests.test_event_stream_paging -q
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api import tasks as tasks_api  # noqa: E402
from app.db.models import Base, Task, TaskEvent  # noqa: E402
from app.orchestrator import _WORKER_TRACE_KINDS  # noqa: E402


class StreamHelperTests(unittest.TestCase):
    def test_llm_round_start_not_persisted(self):
        self.assertNotIn("llm_round_start", _WORKER_TRACE_KINDS)

    def test_refill_still_hidden(self):
        self.assertFalse(tasks_api._stream_event_visible("refill", "info"))
        self.assertFalse(tasks_api._stream_event_visible("refill", "warn"))


class StreamPagingDbTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        db = Path(self._tmpdir.name) / "t.db"
        self.engine = create_async_engine(f"sqlite+aiosqlite:///{db}", future=True)
        self.session_local = async_sessionmaker(self.engine, expire_on_commit=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with self.session_local() as s:
            s.add(Task(id="task-ev", name="t", status="running"))
            kinds = [
                ("refill", "info", "t1"),
                ("worker_start", "info", "t1"),
                ("llm_round_start", "info", "t1"),
                ("tool_http", "info", "t1"),
                ("target_done", "info", "t1"),
                ("llm_error", "error", "t1"),
                ("worker_start", "info", "t2"),
            ]
            for kind, level, tid in kinds:
                s.add(TaskEvent(
                    task_id="task-ev", agent="worker", kind=kind, level=level,
                    message=kind, payload={"target_id": tid, "round": 1},
                ))
            await s.commit()

    async def asyncTearDown(self):
        await self.engine.dispose()
        self._tmpdir.cleanup()

    async def test_fetch_filters_noise_and_pages(self):
        async with self.session_local() as s:
            page = await tasks_api._fetch_stream_events(s, "task-ev", limit=2)
        kinds = [e["kind"] for e in page["items"]]
        self.assertTrue(page["has_more"])
        self.assertEqual(len(page["items"]), 2)
        self.assertNotIn("refill", kinds)
        self.assertNotIn("tool_http", kinds)
        self.assertNotIn("llm_round_start", kinds)
        self.assertTrue(all("id" in e for e in page["items"]))

        oldest = page["items"][-1]["id"]
        async with self.session_local() as s:
            older = await tasks_api._fetch_stream_events(s, "task-ev", limit=10, before_id=oldest)
        self.assertFalse(older["has_more"])
        self.assertTrue(all(e["id"] < oldest for e in older["items"]))

    async def test_target_payload_filter(self):
        from sqlalchemy import select
        async with self.session_local() as s:
            rows = (await s.execute(
                select(TaskEvent).where(tasks_api._target_payload_clause("task-ev", "t2"))
            )).scalars().all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind, "worker_start")
        self.assertEqual(rows[0].payload["target_id"], "t2")


if __name__ == "__main__":
    unittest.main()
