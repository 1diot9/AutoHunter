"""缓存命中率：usage 解析 + miss 补齐，避免 hit/(hit+0) 显示成 100%。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class ReconcileCacheTokensTests(unittest.TestCase):
    def test_missing_miss_uses_prompt_minus_hit(self):
        from app.llm.usage import reconcile_cache_tokens

        hit, miss = reconcile_cache_tokens(1000, 700, 0)
        self.assertEqual((hit, miss), (700, 300))

    def test_full_hit_stays_zero_miss(self):
        from app.llm.usage import reconcile_cache_tokens

        hit, miss = reconcile_cache_tokens(1000, 1000, 0)
        self.assertEqual((hit, miss), (1000, 0))

    def test_no_cache_fields_left_untouched(self):
        from app.llm.usage import reconcile_cache_tokens

        hit, miss = reconcile_cache_tokens(1000, 0, 0)
        self.assertEqual((hit, miss), (0, 0))

    def test_hit_capped_to_prompt(self):
        from app.llm.usage import reconcile_cache_tokens

        hit, miss = reconcile_cache_tokens(100, 999, 0)
        self.assertEqual((hit, miss), (100, 0))

    def test_cache_reported_zero_hit_fills_miss(self):
        from app.llm.usage import reconcile_cache_tokens

        hit, miss = reconcile_cache_tokens(500, 0, 0, cache_reported=True)
        self.assertEqual((hit, miss), (0, 500))


class ParseCompletionUsageTests(unittest.TestCase):
    def test_deepseek_hit_and_miss(self):
        from app.llm.client import parse_completion_usage

        out = parse_completion_usage({
            "prompt_tokens": 1000,
            "completion_tokens": 20,
            "prompt_cache_hit_tokens": 850,
            "prompt_cache_miss_tokens": 150,
        })
        self.assertEqual(out["cache_hit_tokens"], 850)
        self.assertEqual(out["cache_miss_tokens"], 150)

    def test_openai_cached_tokens_only(self):
        from app.llm.client import parse_completion_usage

        out = parse_completion_usage({
            "prompt_tokens": 1000,
            "completion_tokens": 10,
            "prompt_tokens_details": {"cached_tokens": 600},
        })
        self.assertEqual(out["cache_hit_tokens"], 600)
        self.assertEqual(out["cache_miss_tokens"], 400)

    def test_anthropic_creation_is_not_miss(self):
        from app.llm.client import parse_completion_usage

        out = parse_completion_usage({
            "input_tokens": 1000,
            "output_tokens": 30,
            "cache_read_input_tokens": 800,
            "cache_creation_input_tokens": 120,
        })
        self.assertEqual(out["prompt_tokens"], 1000)
        self.assertEqual(out["cache_hit_tokens"], 800)
        self.assertEqual(out["cache_miss_tokens"], 200)

    def test_model_extra_fields_survive_sdk_strip(self):
        from app.llm.client import parse_completion_usage

        usage = SimpleNamespace(
            prompt_tokens=2000,
            completion_tokens=5,
            total_tokens=2005,
            model_extra={"prompt_cache_hit_tokens": 1500, "prompt_cache_miss_tokens": 500},
        )
        out = parse_completion_usage(usage)
        self.assertEqual(out["cache_hit_tokens"], 1500)
        self.assertEqual(out["cache_miss_tokens"], 500)

    def test_no_cache_fields_does_not_invent_miss(self):
        from app.llm.client import parse_completion_usage

        out = parse_completion_usage({"prompt_tokens": 100, "completion_tokens": 8})
        self.assertEqual(out["cache_hit_tokens"], 0)
        self.assertEqual(out["cache_miss_tokens"], 0)


class SnapshotReconcileTests(unittest.TestCase):
    def test_apply_cache_reconcile_fixes_old_rows(self):
        from app.llm.usage import apply_cache_reconcile

        row = apply_cache_reconcile({
            "prompt_tokens": 1_000_000,
            "cache_hit_tokens": 900_000,
            "cache_miss_tokens": 0,
        })
        self.assertEqual(row["cache_miss_tokens"], 100_000)
        self.assertAlmostEqual(row["cache_hit_tokens"] / row["prompt_tokens"], 0.9)
