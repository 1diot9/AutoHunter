"""LLM 端点线程配额：进程内 inflight/queued，按权重档 + 利用率选端点。

高权重端点的线程全部占满后，才开始使用更低权重端点；同权重按利用率均分。
健康端点全部满员时调用方排队等待，不突破 max_threads 总和。
"""
from __future__ import annotations

import threading
from typing import Any, Iterable, Sequence

from app.config import LLMConfig
from app.llm.health import provider_ref, snapshot as health_snapshot


_LOCK = threading.Condition()
_SLOTS: dict[str, dict[str, Any]] = {}
_WAITERS = 0
_WAIT_SLICE_SECONDS = 1.0
_DEFAULT_MAX_THREADS = 4
_MAX_THREADS_CAP = 64


def clamp_max_threads(value: Any, default: int = _DEFAULT_MAX_THREADS) -> int:
    try:
        threads = int(value)
    except (TypeError, ValueError):
        threads = default
    return max(1, min(threads, _MAX_THREADS_CAP))


def provider_max_threads(provider: LLMConfig) -> int:
    return clamp_max_threads(getattr(provider, "max_threads", _DEFAULT_MAX_THREADS))


def _row(ref: str) -> dict[str, Any]:
    row = _SLOTS.get(ref)
    if row is None:
        row = {
            "ref": ref,
            "inflight": 0,
            "queued": 0,
            "max_threads": _DEFAULT_MAX_THREADS,
        }
        _SLOTS[ref] = row
    return row


def _provider_weight(provider: LLMConfig) -> int:
    try:
        weight = int(getattr(provider, "weight", 1) or 1)
    except (TypeError, ValueError):
        weight = 1
    return max(1, min(weight, 100))


def _ref_of(provider: LLMConfig) -> str:
    return provider_ref(
        provider.base_url, provider.model, provider.api_key, provider.protocol
    )


def _health_blocks(ref: str, health: dict[str, dict[str, Any]]) -> bool:
    """True when the endpoint should not receive new work (cooldown/failed/busy probe)."""
    state = health.get(ref) or {}
    status = str(state.get("status") or "ok")
    if status in {"failed", "cooldown"}:
        return True
    if status == "half_open" and state.get("half_open_inflight"):
        return True
    if str(state.get("behavior_status") or "ok") in {"failed", "cooldown"}:
        return True
    # behavior half-open 不在这里拦截：acquire_provider_slot 按 owner 放行探测 worker，
    # 其它 owner 会拿到 behavior_half_open_inflight。这里一拦，认领探测的 worker 下一轮
    # 也无法再打到这个端点，界面会一直停在「探测中」。
    return False


def _utilization(inflight: int, max_threads: int) -> float:
    cap = max(1, max_threads)
    return inflight / cap


def _pick(
    providers: Sequence[LLMConfig],
    sticky_ref: str = "",
    *,
    exclude_refs: Iterable[str] | None = None,
) -> LLMConfig | None:
    """Pick one under-capacity healthy provider, or None if none have spare slots.

    Returns None when every candidate is either unhealthy or at capacity.
    Distinguishes "all full" vs "all unhealthy" via caller checking health again.
    """
    excluded = {str(item or "") for item in (exclude_refs or ()) if item}
    health = health_snapshot()
    candidates: list[tuple[int, LLMConfig, str, int, int]] = []
    for index, provider in enumerate(providers):
        if not getattr(provider, "enabled", True):
            continue
        ref = _ref_of(provider)
        if ref in excluded:
            continue
        if _health_blocks(ref, health):
            continue
        max_threads = provider_max_threads(provider)
        row = _row(ref)
        row["max_threads"] = max_threads
        inflight = int(row.get("inflight") or 0)
        if inflight >= max_threads:
            continue
        candidates.append((index, provider, ref, _provider_weight(provider), max_threads))

    if not candidates:
        return None

    top_weight = max(weight for _index, _provider, _ref, weight, _cap in candidates)
    tier = [
        (index, provider, ref, max_threads)
        for index, provider, ref, weight, max_threads in candidates
        if weight == top_weight
    ]

    if sticky_ref:
        for index, provider, ref, max_threads in tier:
            if ref == sticky_ref:
                return provider

    def sort_key(item: tuple[int, LLMConfig, str, int]) -> tuple[float, int, int]:
        index, _provider, ref, max_threads = item
        inflight = int(_row(ref).get("inflight") or 0)
        return (_utilization(inflight, max_threads), inflight, index)

    _index, provider, _ref, _cap = min(tier, key=sort_key)
    return provider


def _any_healthy_capacity(
    providers: Sequence[LLMConfig],
    *,
    exclude_refs: Iterable[str] | None = None,
) -> tuple[bool, bool]:
    """Return (has_healthy, has_spare).

    has_healthy: at least one enabled provider not blocked by health.
    has_spare: at least one healthy provider with inflight < max_threads.
    """
    excluded = {str(item or "") for item in (exclude_refs or ()) if item}
    health = health_snapshot()
    has_healthy = False
    for provider in providers:
        if not getattr(provider, "enabled", True):
            continue
        ref = _ref_of(provider)
        if ref in excluded:
            continue
        if _health_blocks(ref, health):
            continue
        has_healthy = True
        max_threads = provider_max_threads(provider)
        row = _row(ref)
        row["max_threads"] = max_threads
        if int(row.get("inflight") or 0) < max_threads:
            return True, True
    return has_healthy, False


def acquire(
    providers: Sequence[LLMConfig],
    sticky_ref: str = "",
    *,
    exclude_refs: Iterable[str] | None = None,
    timeout: float | None = None,
) -> LLMConfig | None:
    """Claim one thread slot on a selected provider.

    Blocks while every healthy endpoint is at capacity. Returns None when no
    healthy endpoint remains (caller should surface cooldown / no-endpoint).
    """
    import time as _time

    if not providers:
        return None
    deadline = (
        _time.monotonic() + max(0.0, float(timeout))
        if timeout is not None
        else None
    )

    global _WAITERS
    queued = False
    try:
        with _LOCK:
            while True:
                picked = _pick(providers, sticky_ref, exclude_refs=exclude_refs)
                if picked is not None:
                    ref = _ref_of(picked)
                    row = _row(ref)
                    row["max_threads"] = provider_max_threads(picked)
                    row["inflight"] = int(row.get("inflight") or 0) + 1
                    return picked

                has_healthy, has_spare = _any_healthy_capacity(
                    providers, exclude_refs=exclude_refs
                )
                if has_spare:
                    # Race: spare appeared between _pick and re-check; loop again.
                    continue
                if not has_healthy:
                    return None

                # All healthy endpoints are full — queue and wait.
                if not queued:
                    queued = True
                    _WAITERS += 1

                if deadline is not None:
                    remaining = deadline - _time.monotonic()
                    if remaining <= 0:
                        return None
                    _LOCK.wait(timeout=min(_WAIT_SLICE_SECONDS, remaining))
                else:
                    _LOCK.wait(timeout=_WAIT_SLICE_SECONDS)
    finally:
        if queued:
            with _LOCK:
                _WAITERS = max(0, _WAITERS - 1)


def release(provider_or_ref: LLMConfig | str) -> None:
    """Release one thread slot and wake one waiter."""
    if isinstance(provider_or_ref, str):
        ref = provider_or_ref
    else:
        ref = _ref_of(provider_or_ref)
    with _LOCK:
        row = _row(ref)
        row["inflight"] = max(0, int(row.get("inflight") or 0) - 1)
        _LOCK.notify()


def update_caps(providers: Sequence[LLMConfig] | Iterable[dict[str, Any]]) -> None:
    """Refresh remembered caps from settings; wake waiters when capacity grows."""
    grew = False
    with _LOCK:
        for item in providers:
            if isinstance(item, LLMConfig):
                ref = _ref_of(item)
                new_cap = provider_max_threads(item)
            else:
                base_url = str(item.get("base_url") or "")
                model = str(item.get("model") or "")
                api_key = str(item.get("api_key") or "")
                protocol = str(item.get("protocol") or "auto")
                if not (base_url and model and api_key):
                    continue
                ref = provider_ref(base_url, model, api_key, protocol)
                new_cap = clamp_max_threads(item.get("max_threads", _DEFAULT_MAX_THREADS))
            row = _row(ref)
            old_cap = int(row.get("max_threads") or _DEFAULT_MAX_THREADS)
            row["max_threads"] = new_cap
            if new_cap > old_cap:
                grew = True
        if grew:
            _LOCK.notify_all()


def snapshot() -> dict[str, dict[str, Any]]:
    """Per-ref slot view for settings / provider-health APIs."""
    with _LOCK:
        waiters = _WAITERS
        out: dict[str, dict[str, Any]] = {}
        for ref, row in _SLOTS.items():
            inflight = int(row.get("inflight") or 0)
            max_threads = clamp_max_threads(row.get("max_threads", _DEFAULT_MAX_THREADS))
            out[ref] = {
                "ref": ref,
                "inflight": inflight,
                "max_threads": max_threads,
                "queued": waiters,
                "utilization": round(_utilization(inflight, max_threads), 4),
            }
        return out


def slot_view_for(
    base_url: str,
    model: str,
    api_key: str = "",
    protocol: str = "auto",
    max_threads: int | None = None,
) -> dict[str, Any]:
    """Merge-friendly slot fields for a known provider identity."""
    ref = provider_ref(base_url, model, api_key, protocol)
    cap = clamp_max_threads(
        max_threads if max_threads is not None else _DEFAULT_MAX_THREADS
    )
    with _LOCK:
        row = _SLOTS.get(ref) or {}
        inflight = int(row.get("inflight") or 0)
        remembered = int(row.get("max_threads") or 0)
        if remembered > 0:
            cap = clamp_max_threads(remembered)
        waiters = _WAITERS
    return {
        "inflight": inflight,
        "max_threads": cap,
        "queued": waiters,
        "utilization": round(_utilization(inflight, cap), 4),
    }


def reset_for_tests() -> None:
    """Clear process-local slot state (unit tests only)."""
    global _WAITERS
    with _LOCK:
        _SLOTS.clear()
        _WAITERS = 0
        _LOCK.notify_all()
