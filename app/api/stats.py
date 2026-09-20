"""日历统计 API：按日期聚合产出 + Token 成本。

产出统计从 findings/reviews 表按 CST 日期对应的 UTC 半开区间过滤（可走 created_at 索引）；
Token 成本从 token_usage_daily 表读取，按 pricing 配置实时计算。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Finding, Killsweep, Review
from app.db.session import engine, get_session
from app.llm.usage import apply_cache_reconcile, pending_deltas, query_usage_by_date, query_usage_date_range
from app.settings_service import resolve_pricing

router = APIRouter(prefix="/api/stats", tags=["stats"])

CST = timezone(timedelta(hours=8))


def _cst_day_utc_range(date_str: str) -> tuple[datetime, datetime]:
    """CST 日历日 YYYY-MM-DD → UTC naive 半开区间 [start, end)。

    DB 存 UTC naive；CST 00:00 = 前一天 UTC 16:00。
    """
    y, m, d = map(int, date_str.split("-"))
    start_cst = datetime(y, m, d, tzinfo=CST)
    end_cst = start_cst + timedelta(days=1)
    start_utc = start_cst.astimezone(timezone.utc).replace(tzinfo=None)
    end_utc = end_cst.astimezone(timezone.utc).replace(tzinfo=None)
    return start_utc, end_utc


def _month_utc_range(month: str) -> tuple[datetime, datetime] | None:
    """YYYY-MM → 该月 CST 起止对应的 UTC naive 半开区间。"""
    try:
        year, mon = map(int, month.split("-"))
        start_cst = datetime(year, mon, 1, tzinfo=CST)
        if mon == 12:
            end_cst = datetime(year + 1, 1, 1, tzinfo=CST)
        else:
            end_cst = datetime(year, mon + 1, 1, tzinfo=CST)
    except (ValueError, IndexError):
        return None
    return (
        start_cst.astimezone(timezone.utc).replace(tzinfo=None),
        end_cst.astimezone(timezone.utc).replace(tzinfo=None),
    )


def _in_utc_range(col, start: datetime, end: datetime):
    return and_(col >= start, col < end)


def _calc_cost(prompt_tokens: int, completion_tokens: int,
               cache_hit_tokens: int, pricing: dict) -> float:
    """按模型计价计算单行成本（元）。"""
    price_in = float(pricing.get("input", 0) or 0)
    price_out = float(pricing.get("output", 0) or 0)
    price_cache = float(pricing.get("cache_hit", 0) or 0)
    non_cache_input = max(0, prompt_tokens - cache_hit_tokens)
    cost = (
        non_cache_input * price_in / 1_000_000
        + completion_tokens * price_out / 1_000_000
        + cache_hit_tokens * price_cache / 1_000_000
    )
    return round(cost, 4)


@router.get("/pool")
async def pool_stats():
    """数据库连接池实时状态（不需要 DB session，不消耗连接）。"""
    pool = engine.pool
    return {
        "pool_size": pool.size(),
        "max_overflow": pool._max_overflow,
        "checkedout": pool.checkedout(),
        "checkedin": pool.checkedin(),
        "overflow": pool.overflow(),
        "total_capacity": pool.size() + pool._max_overflow,
        "timeout": pool._timeout,
    }


@router.get("/daily")
async def daily_stats(
    date: str = Query(None, description="YYYY-MM-DD，默认今天 CST"),
    session: AsyncSession = Depends(get_session),
):
    """指定日期的产出统计 + Token 成本明细。"""
    if not date:
        date = datetime.now(CST).strftime("%Y-%m-%d")

    start_utc, end_utc = _cst_day_utc_range(date)
    day_f = _in_utc_range(Finding.created_at, start_utc, end_utc)
    day_ks = _in_utc_range(Killsweep.created_at, start_utc, end_utc)

    # findings：总数 + status 分布一次 GROUP BY
    status_q = (
        select(Finding.status, func.count(Finding.id))
        .where(day_f)
        .group_by(Finding.status)
    )
    status_counts = {row[0]: row[1] for row in (await session.execute(status_q)).all()}
    findings_total = sum(status_counts.values())
    pending_review = status_counts.get("pending_review", 0)
    reviewed = status_counts.get("reviewed", 0)

    # reviews：verdict + user_status + submitted 一次 GROUP BY（join findings 用区间）
    review_agg_q = (
        select(Review.verdict, Review.user_status, Review.submitted, func.count(Review.id))
        .join(Finding, Review.finding_id == Finding.id)
        .where(day_f)
        .group_by(Review.verdict, Review.user_status, Review.submitted)
    )
    verdict_counts: dict[str, int] = {}
    user_status_counts: dict[str, int] = {}
    submitted_count = 0
    for verdict, user_status, submitted, cnt in (await session.execute(review_agg_q)).all():
        if verdict:
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + cnt
        if verdict == "accepted" and user_status:
            user_status_counts[user_status] = user_status_counts.get(user_status, 0) + cnt
        if verdict == "accepted" and submitted:
            submitted_count += cnt

    ks_q = (
        select(func.count(Killsweep.id))
        .where(day_ks)
        .where(Killsweep.is_killsweep == True)  # noqa: E712
    )
    killsweep_count = (await session.execute(ks_q)).scalar() or 0

    archived_q = (
        select(func.count(Finding.id))
        .join(Review, Review.finding_id == Finding.id)
        .where(day_f)
        .where(Review.verdict.in_(["ignored", "deepen"]))
        .where(Review.user_status == "pending")
        .where(Finding.status != "superseded")
    )
    archived_count = (await session.execute(archived_q)).scalar() or 0

    # task_ids：accepted 三状态一次扫
    user_status_tasks_q = (
        select(Review.user_status, Review.task_id)
        .join(Finding, Review.finding_id == Finding.id)
        .where(day_f)
        .where(Review.verdict == "accepted")
    )
    user_status_task_ids = {"pending": set(), "passed": set(), "rejected": set()}
    for row in (await session.execute(user_status_tasks_q)).all():
        status, tid = row[0], row[1]
        if status in user_status_task_ids and tid:
            user_status_task_ids[status].add(tid)

    submitted_tasks_q = (
        select(Review.task_id)
        .join(Finding, Review.finding_id == Finding.id)
        .where(day_f)
        .where(Review.verdict == "accepted")
        .where(Review.submitted == True)  # noqa: E712
        .distinct()
    )
    submitted_task_ids = [r[0] for r in (await session.execute(submitted_tasks_q)).all() if r[0]]

    ks_tasks_q = (
        select(Killsweep.task_id)
        .where(day_ks)
        .where(Killsweep.is_killsweep == True)  # noqa: E712
        .distinct()
    )
    killsweep_task_ids = [r[0] for r in (await session.execute(ks_tasks_q)).all() if r[0]]

    archived_tasks_q = (
        select(Finding.task_id)
        .join(Review, Review.finding_id == Finding.id)
        .where(day_f)
        .where(Review.verdict.in_(["ignored", "deepen"]))
        .where(Review.user_status == "pending")
        .where(Finding.status != "superseded")
        .distinct()
    )
    archived_task_ids = [r[0] for r in (await session.execute(archived_tasks_q)).all() if r[0]]

    token_rows = query_usage_by_date(date)
    pricing_config = resolve_pricing()
    token_by_model: dict[str, dict] = {}
    today = datetime.now(CST).strftime("%Y-%m-%d")
    for row in token_rows:
        model, pt, ct, cht, cmt, req = row
        token_by_model[model or ""] = {
            "prompt_tokens": pt or 0,
            "completion_tokens": ct or 0,
            "cache_hit_tokens": cht or 0,
            "cache_miss_tokens": cmt or 0,
            "requests": req or 0,
        }
    if date == today:
        for _tid, mdl, delta in pending_deltas():
            row = token_by_model.setdefault(mdl or "", {
                "prompt_tokens": 0, "completion_tokens": 0,
                "cache_hit_tokens": 0, "cache_miss_tokens": 0, "requests": 0,
            })
            row["prompt_tokens"] += delta.get("prompt_tokens", 0)
            row["completion_tokens"] += delta.get("completion_tokens", 0)
            row["cache_hit_tokens"] += delta.get("cache_hit_tokens", 0)
            row["cache_miss_tokens"] += delta.get("cache_miss_tokens", 0)
            row["requests"] += delta.get("requests", 0)

    by_model = []
    total_cost = 0.0
    total_prompt = 0
    total_completion = 0
    total_cache_hit = 0
    total_requests = 0
    for model, raw in token_by_model.items():
        usage_row = apply_cache_reconcile({
            "prompt_tokens": raw["prompt_tokens"],
            "completion_tokens": raw["completion_tokens"],
            "cache_hit_tokens": raw["cache_hit_tokens"],
            "cache_miss_tokens": raw["cache_miss_tokens"],
        })
        pt = usage_row["prompt_tokens"]
        ct = usage_row["completion_tokens"]
        cht = usage_row["cache_hit_tokens"]
        cmt = usage_row["cache_miss_tokens"]
        req = raw["requests"]
        pricing = pricing_config.get(model, {}) if model else {}
        cost = _calc_cost(pt, ct, cht, pricing)
        by_model.append({
           "model": model,
           "prompt_tokens": pt,
           "completion_tokens": ct,
           "cache_hit_tokens": cht,
           "cache_miss_tokens": cmt,
           "requests": req,
           "cost": cost,
           "pricing": pricing,
        })
        total_cost += cost
        total_prompt += pt
        total_completion += ct
        total_cache_hit += cht
        total_requests += req

    return {
        "date": date,
        "findings": {
            "total": findings_total,
            "pending_review": pending_review,
            "reviewed": reviewed,
        },
        "reviews": {
            "accepted": verdict_counts.get("accepted", 0),
            "ignored": verdict_counts.get("ignored", 0),
            "deepen": verdict_counts.get("deepen", 0),
        },
        "user_reviews": {
            "pending": user_status_counts.get("pending", 0),
            "passed": user_status_counts.get("passed", 0),
            "rejected": user_status_counts.get("rejected", 0),
            "submitted": submitted_count,
        },
        "killsweep": killsweep_count,
        "archived": archived_count,
        "task_ids": {
            "pending": sorted(user_status_task_ids.get("pending", set())),
            "passed": sorted(user_status_task_ids.get("passed", set())),
            "rejected": sorted(user_status_task_ids.get("rejected", set())),
            "submitted": submitted_task_ids,
            "killsweep": killsweep_task_ids,
            "archived": archived_task_ids,
        },
        "token_usage": {
            "total_cost": round(total_cost, 4),
            "total_prompt_tokens": total_prompt,
            "total_completion_tokens": total_completion,
            "total_cache_hit_tokens": total_cache_hit,
            "total_requests": total_requests,
            "by_model": by_model,
        },
    }


@router.get("/daily-overview")
async def daily_overview(
    month: str = Query(None, description="YYYY-MM，默认当月 CST"),
    session: AsyncSession = Depends(get_session),
):
    """月度日历概览：每天一行汇总，用于日历格着色。"""
    if not month:
        month = datetime.now(CST).strftime("%Y-%m")

    rng = _month_utc_range(month)
    if rng is None:
        return {"month": month, "days": []}
    start_utc, end_utc = rng
    month_f = _in_utc_range(Finding.created_at, start_utc, end_utc)

    # SQLite：按 CST 日期分组 — 用 datetime(+8h) 仅用于 GROUP BY 标签，过滤已走索引区间
    cst_day = func.date(func.datetime(Finding.created_at, "+8 hours"))

    findings_q = (
        select(cst_day.label("d"), func.count(Finding.id))
        .where(month_f)
        .group_by(cst_day)
    )
    findings_by_day = {row[0]: row[1] for row in (await session.execute(findings_q)).all()}

    accepted_q = (
        select(cst_day.label("d"), func.count(Review.id))
        .join(Finding, Review.finding_id == Finding.id)
        .where(Review.verdict == "accepted")
        .where(month_f)
        .group_by(cst_day)
    )
    accepted_by_day = {row[0]: row[1] for row in (await session.execute(accepted_q)).all()}

    submitted_q = (
        select(cst_day.label("d"), func.count(Review.id))
        .join(Finding, Review.finding_id == Finding.id)
        .where(Review.submitted == True)  # noqa: E712
        .where(month_f)
        .group_by(cst_day)
    )
    submitted_by_day = {row[0]: row[1] for row in (await session.execute(submitted_q)).all()}

    pricing_config = resolve_pricing()
    # 月范围字符串：CST 月起止
    try:
        year, mon = map(int, month.split("-"))
        month_start = f"{year:04d}-{mon:02d}-01"
        if mon == 12:
            month_end = f"{year + 1:04d}-01-01"
        else:
            month_end = f"{year:04d}-{mon + 1:02d}-01"
    except (ValueError, IndexError):
        return {"month": month, "days": []}

    token_model_rows = query_usage_date_range(month_start, month_end)

    cost_by_day: dict[str, float] = {}
    requests_by_day: dict[str, int] = {}
    for row in token_model_rows:
        d, model, pt, ct, cht = row
        pricing = pricing_config.get(model, {}) if model else {}
        cost = _calc_cost(pt, ct, cht, pricing)
        cost_by_day[d] = round(cost_by_day.get(d, 0) + cost, 4)
        requests_by_day[d] = requests_by_day.get(d, 0) + 1

    today = datetime.now(CST).strftime("%Y-%m-%d")
    if month_start <= today < month_end:
        pending_by_model: dict[str, dict[str, int]] = {}
        for _tid, mdl, delta in pending_deltas():
            row = pending_by_model.setdefault(mdl or "", {
                "prompt_tokens": 0, "completion_tokens": 0, "cache_hit_tokens": 0, "requests": 0,
            })
            row["prompt_tokens"] += delta.get("prompt_tokens", 0)
            row["completion_tokens"] += delta.get("completion_tokens", 0)
            row["cache_hit_tokens"] += delta.get("cache_hit_tokens", 0)
            row["requests"] += delta.get("requests", 0)
        for model, raw in pending_by_model.items():
            pricing = pricing_config.get(model, {}) if model else {}
            cost = _calc_cost(raw["prompt_tokens"], raw["completion_tokens"], raw["cache_hit_tokens"], pricing)
            cost_by_day[today] = round(cost_by_day.get(today, 0) + cost, 4)
            requests_by_day[today] = requests_by_day.get(today, 0) + raw["requests"]

    all_dates = set(findings_by_day.keys()) | set(accepted_by_day.keys()) | set(submitted_by_day.keys()) | set(cost_by_day.keys())
    days = []
    for d in sorted(all_dates):
        days.append({
            "date": d,
            "findings_total": findings_by_day.get(d, 0),
            "accepted": accepted_by_day.get(d, 0),
            "submitted": submitted_by_day.get(d, 0),
            "cost": cost_by_day.get(d, 0),
            "requests": requests_by_day.get(d, 0),
        })

    return {"month": month, "days": days}
