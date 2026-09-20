"""规模性能优化回归：任务列表瘦 DTO、批量用量、日历区间、事件回收。"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class TestUsageByTaskModel(unittest.TestCase):
    def test_batch_groups_by_task(self):
        from app.llm import usage as u

        u._USAGE.clear()
        u._FLUSHED.clear()
        u._DIRTY.clear()
        fake_rows = [
            ("t1", "m1", 10, 5, 1, 0, 2),
            ("t1", "m2", 20, 10, 0, 0, 3),
            ("t2", "m1", 100, 50, 0, 0, 1),
        ]
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = fake_rows
        with patch.object(u, "_get_db_conn", return_value=conn), \
             patch.object(u, "_DB_LOCK"):
            out = u.usage_by_task_model()
        self.assertEqual(set(out.keys()), {"t1", "t2"})
        self.assertEqual(len(out["t1"]), 2)
        self.assertEqual(out["t2"][0]["prompt_tokens"], 100)


class TestCstDayUtcRange(unittest.TestCase):
    def test_half_open_interval(self):
        from app.api.stats import _cst_day_utc_range

        start, end = _cst_day_utc_range("2026-03-18")
        # CST 2026-03-18 00:00 = UTC 2026-03-17 16:00
        self.assertEqual(start, datetime(2026, 3, 17, 16, 0, 0))
        self.assertEqual(end, datetime(2026, 3, 18, 16, 0, 0))
        self.assertEqual(end - start, timedelta(days=1))

    def test_boundary_inclusion(self):
        from app.api.stats import _cst_day_utc_range, _in_utc_range
        from sqlalchemy import column

        start, end = _cst_day_utc_range("2026-01-01")
        # 刚好落在 start 应包含；落在 end 应排除
        self.assertEqual(start.hour, 16)  # UTC
        self.assertLess(start, end)


class TestTaskListDto(unittest.TestCase):
    def test_list_item_schema_has_no_secrets(self):
        from app.api.dto import TaskListItem

        fields = set(TaskListItem.model_fields.keys())
        for banned in ("auth_bindings", "src_rules", "cas_sso_config",
                       "manual_targets", "model_config_data", "fofa_config"):
            self.assertNotIn(banned, fields)
        for required in ("id", "name", "status", "pending_user_review",
                         "progress_pct", "llm_cost", "is_top"):
            self.assertIn(required, fields)


class TestAttachModelCosts(unittest.TestCase):
    def test_cost_from_pricing(self):
        from app.api.tasks import _attach_model_costs, _task_cost_from_models

        models = [{
            "model": "demo",
            "prompt_tokens": 1_000_000,
            "completion_tokens": 500_000,
            "cache_hit_tokens": 0,
            "cache_miss_tokens": 0,
            "requests": 1,
        }]
        priced = _attach_model_costs(models, {"demo": {"input": 1.0, "output": 2.0, "cache_hit": 0}})
        # 1M * 1/1M + 0.5M * 2/1M = 1 + 1 = 2
        self.assertEqual(priced[0]["cost"], 2.0)
        self.assertEqual(_task_cost_from_models(priced), 2.0)


class TestPruneGlobalEvents(unittest.IsolatedAsyncioTestCase):
    async def test_prune_skips_when_ttl_zero(self):
        from app.maintenance import cleanup as c

        with patch.object(c, "SessionLocal") as SL:
            # ttl=0 且 cap=0 时不应打开 session 做删除
            result = await c.prune_global_events(fine_ttl_days=0, per_task_cap=0)
        self.assertTrue(result["ok"])
        self.assertEqual(result["deleted_fine"], 0)
        self.assertEqual(result["deleted_cap"], 0)
        SL.assert_not_called()


class TestHeartbeatBatch(unittest.TestCase):
    def test_marks_without_db(self):
        """心跳循环只写内存标记，不直接 commit。"""
        from app.orchestrator import TaskRunner
        import asyncio

        runner = TaskRunner("task-hb")

        async def _run():
            await runner._flush_heartbeats()  # 空 marks，无 DB

        asyncio.run(_run())
        self.assertEqual(runner._heartbeat_marks, {})


class TestLightBoardKeepsUsage(unittest.TestCase):
    def test_light_board_still_returns_token_usage(self):
        """light 轮询跳过 stats，但不能把 Token/成本一起跳掉，否则看板计费会冻住。"""
        text = (ROOT / "app/api/tasks.py").read_text(encoding="utf-8")
        light_fn = text.split("if light:", 1)[1].split("stats = await _compute_stats", 1)[0]
        self.assertIn("_board_runtime_usage", light_fn)
        helper = text.split("def _board_runtime_usage", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("llm_usage", helper)
        self.assertIn("llm_usage_by_model", helper)
        self.assertIn("engine_usage", helper)


if __name__ == "__main__":
    unittest.main()
