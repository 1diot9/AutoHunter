"""进程心跳：独立守护线程写时间戳，不走 asyncio。

事件循环被 SQLite / JSON 卡住时，/health 会超时，但这个线程只要进程还活着就会继续跳。
看门狗据此区分「事件循环短暂卡顿」和「进程真死」，避免误杀容器。
"""
from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_PATH = os.environ.get("AUTOHUNTER_HEARTBEAT_PATH", "/tmp/autohunter.heartbeat")
INTERVAL = float(os.environ.get("AUTOHUNTER_HEARTBEAT_INTERVAL", "2"))

_stop = threading.Event()
_thread: threading.Thread | None = None
_path = DEFAULT_PATH


def heartbeat_path() -> str:
    return _path


def heartbeat_age_seconds(path: str | None = None) -> float | None:
    """心跳文件距现在的秒数；文件不存在则返回 None。"""
    target = Path(path or _path)
    try:
        return max(0.0, time.time() - target.stat().st_mtime)
    except OSError:
        return None


def _write_beat(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(f"{time.time():.3f}\n", encoding="utf-8")
    tmp.replace(path)


def start_heartbeat(path: str | None = None, interval: float | None = None) -> None:
    """启动守护线程。可重复调用：已在跑则只刷新路径。"""
    global _thread, _path
    _path = path or os.environ.get("AUTOHUNTER_HEARTBEAT_PATH", DEFAULT_PATH)
    wait = INTERVAL if interval is None else float(interval)
    beat = Path(_path)
    try:
        _write_beat(beat)
    except OSError as exc:
        logger.warning("heartbeat initial write failed path=%s err=%s", _path, exc)

    if _thread and _thread.is_alive():
        return

    _stop.clear()

    def _loop() -> None:
        while not _stop.wait(wait):
            try:
                _write_beat(Path(_path))
            except OSError:
                logger.debug("heartbeat write failed path=%s", _path, exc_info=True)

    _thread = threading.Thread(target=_loop, name="ah-heartbeat", daemon=True)
    _thread.start()


def stop_heartbeat() -> None:
    global _thread
    _stop.set()
    thread = _thread
    if thread and thread.is_alive():
        thread.join(timeout=1.5)
    _thread = None
