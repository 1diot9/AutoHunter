"""进程心跳线程：事件循环卡住时仍能写时间戳。

运行：
  python -m unittest tests.test_heartbeat -q
"""
from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import heartbeat  # noqa: E402


class HeartbeatTests(unittest.TestCase):
    def setUp(self):
        heartbeat.stop_heartbeat()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "ah.heartbeat")

    def tearDown(self):
        heartbeat.stop_heartbeat()
        self.tmp.cleanup()

    def test_writes_and_reports_fresh_age(self):
        heartbeat.start_heartbeat(path=self.path, interval=0.05)
        deadline = time.time() + 2
        while time.time() < deadline and not Path(self.path).exists():
            time.sleep(0.02)
        self.assertTrue(Path(self.path).exists())
        age = heartbeat.heartbeat_age_seconds(self.path)
        self.assertIsNotNone(age)
        self.assertLess(age, 2)

    def test_missing_file_is_none(self):
        self.assertIsNone(heartbeat.heartbeat_age_seconds(str(Path(self.tmp.name) / "nope")))


if __name__ == "__main__":
    unittest.main()
