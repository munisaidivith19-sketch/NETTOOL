"""Forecasts: when will a subnet run out of addresses, and when will an uplink be saturated?

- With enough history (14+ days for subnets, 48+ hours for uplinks) we use Prophet, which
  learns the trend plus repeating patterns (weekday vs weekend, day vs night).
- With less history we fit a straight line (linear regression): "it grew by 1.4 addresses a
  day, so at this rate it is full in 41 days".
- With almost no history (< 3 points) we say so instead of guessing.

Prophet is imported only here, inside the functions, because it is large and slow to load.
"""

from __future__ import annotations

import logging
import math
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import date, datetime, timedelta, timezone

logger = logging.getLogger(__name__)

PROPHET_MIN_DAYS = 14
PROPHET_MIN_HOURS = 48
MIN_POINTS = 3
SUBNET_HORIZON_DAYS = 90
SEARCH_HORIZON_DAYS = 365
BANDWIDTH_HORIZON_HOURS = 7 * 24
MODEL_TIMEOUT_SECONDS = 60
WARN_FRACTION = 0.8


def _quiet_prophet() -> None:
    # prophet.plot logs "Importing plotly failed" at ERROR on import: we never plot.
    for name, level in (("prophet", logging.ERROR), ("prophet.plot", logging.CRITICAL),
                        ("cmdstanpy", logging.ERROR)):
        log = logging.getLogger(name)
        log.setLevel(level)
        log.propagate = False
    try:
        # cmdstanpy adds its own INFO handler the first time it logs; create it now and
        # silence it, or the first fit of every run prints "Chain [1] start processing".
        from cmdstanpy.utils import get_logger

        get_logger().setLevel(logging.ERROR)
    except ImportError:
        pass


def _with_timeout(fn, *args):
    """Run a model fit with a time limit; on timeout the caller falls back to a line."""
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(fn, *args).result(timeout=MODEL_TIMEOUT_SECONDS)
    finally:
        pool.shutdown(wait=False)


def _linear(xs: list[float], ys: list[float]):
    """Least-squares line. Returns (slope, intercept, residual standard deviation)."""
    import numpy as np
    from sklearn.linear_model import LinearRegression

    x = np.array(xs, dtype=float).reshape(-1, 1)
    y = np.array(ys, dtype=float)
    model = LinearRegression().fit(x, y)
    residuals = y - model.predict(x)
    spread = float(np.std(residuals)) if len(ys) > 2 else 0.0
    return float(model.coef_[0]), float(model.intercept_), spread


def _prophet(ds: list[datetime], ys: list[float], periods: int, freq: str, daily: bool,
             weekly: bool):
    import pandas as pd

    _quiet_prophet()
    from prophet import Prophet

    _quiet_prophet()  # cmdstanpy attaches its own handler on import
    model = Prophet(daily_seasonality=daily, weekly_seasonality=weekly,
                    yearly_seasonality=False, interval_width=0.8)
    frame = pd.DataFrame({"ds": [d.replace(tzinfo=None) for d in ds], "y": ys})
    model.fit(frame)
    future = model.make_future_dataframe(periods=periods, freq=freq, include_history=False)
    out = model.predict(future)
    return [(row.ds.to_pydatetime().replace(tzinfo=timezone.utc), float(row.yhat),
             float(row.yhat_lower), float(row.yhat_upper)) for row in out.itertuples()]


def _clip(value: float, high: float) -> float:
    return max(0.0, min(value, high))


def subnet_exhaustion(history: list[dict], usable: int, today: date | None = None) -> dict:
    """history: [{"day": "YYYY-MM-DD", "used": n}] (one point per day)."""
    today = today or datetime.now(timezone.utc).date()
    points = sorted({date.fromisoformat(h["day"]): int(h["used"]) for h in history}.items())
    current = points[-1][1] if points else 0
    base = {"usable": usable, "current_used": current, "points": len(points)}
    if len(points) < MIN_POINTS or usable <= 0:
        return base | {"status": "insufficient_data", "method": None, "series": []}

    span = (points[-1][0] - points[0][0]).days
    forecast = None
    method = "linear"
    if len(points) >= PROPHET_MIN_DAYS and span >= PROPHET_MIN_DAYS:
        try:
            ds = [datetime(d.year, d.month, d.day, tzinfo=timezone.utc) for d, _ in points]
            forecast = _with_timeout(_prophet, ds, [float(u) for _, u in points],
                                     SEARCH_HORIZON_DAYS, "D", False, True)
            method = "prophet"
        except (FutureTimeout, Exception) as exc:  # noqa: BLE001 - any model failure → line
            logger.warning("Prophet failed for a subnet (%s); using a straight line",
                           type(exc).__name__)
    origin = points[0][0]
    if forecast is None:
        slope, intercept, spread = _linear([(d - origin).days for d, _ in points],
                                           [u for _, u in points])
        start = (points[-1][0] - origin).days
        forecast = []
        for step in range(1, SEARCH_HORIZON_DAYS + 1):
            x = start + step
            yhat = slope * x + intercept
            band = 1.28 * spread * math.sqrt(1 + step / max(len(points), 1))
            day = points[-1][0] + timedelta(days=step)
            forecast.append((datetime(day.year, day.month, day.day, tzinfo=timezone.utc),
                             yhat, yhat - band, yhat + band))
        growth_per_day = slope
    else:
        growth_per_day = (forecast[29][1] - forecast[0][1]) / 29 if len(forecast) > 29 else 0.0

    def first_day(level: float) -> str | None:
        for ts, yhat, _lo, _hi in forecast:
            if yhat >= level:
                return ts.date().isoformat()
        return None

    full_on = first_day(usable)
    warn_on = first_day(WARN_FRACTION * usable) if current < WARN_FRACTION * usable else None
    days_until_full = (date.fromisoformat(full_on) - today).days if full_on else None
    series = [{"ts": ts.date().isoformat(), "yhat": round(_clip(y, usable), 1),
               "lo": round(_clip(lo, usable), 1), "hi": round(_clip(hi, usable), 1)}
              for ts, y, lo, hi in forecast[:SUBNET_HORIZON_DAYS]]
    status = "growing" if growth_per_day > 0.05 else "stable"
    return base | {"status": status, "method": method,
                   "growth_per_day": round(growth_per_day, 2),
                   "full_on": full_on, "warn_on": warn_on, "days_until_full": days_until_full,
                   "series": series}


def _hourly(points: list[list]) -> list[tuple[datetime, float]]:
    """points: [[epoch_seconds, in_bps, out_bps, errors]] → hourly mean of max(in, out)."""
    buckets: dict[datetime, list[float]] = {}
    for ts, in_bps, out_bps, *_ in points:
        if in_bps is None and out_bps is None:
            continue
        hour = datetime.fromtimestamp(int(ts) // 3600 * 3600, timezone.utc)
        buckets.setdefault(hour, []).append(float(max(in_bps or 0, out_bps or 0)))
    return [(hour, sum(v) / len(v)) for hour, v in sorted(buckets.items())]


def uplink_bandwidth(points: list[list], speed_mbps: int | None) -> dict:
    hourly = _hourly(points)
    capacity = speed_mbps * 1_000_000 if speed_mbps else None
    base = {"speed_mbps": speed_mbps, "points": len(hourly),
            "current_bps": round(hourly[-1][1]) if hourly else None}
    if len(hourly) < 24:
        return base | {"status": "insufficient_data", "method": None, "series": []}
    method = "linear"
    forecast = None
    if len(hourly) >= PROPHET_MIN_HOURS:
        try:
            forecast = _with_timeout(_prophet, [h for h, _ in hourly], [v for _, v in hourly],
                                     BANDWIDTH_HORIZON_HOURS, "h", True,
                                     len(hourly) >= 14 * 24)
            method = "prophet"
        except (FutureTimeout, Exception) as exc:  # noqa: BLE001
            logger.warning("Prophet failed for an uplink (%s); using a straight line",
                           type(exc).__name__)
    if forecast is None:
        origin = hourly[0][0]
        slope, intercept, spread = _linear([(h - origin).total_seconds() / 3600 for h, _ in hourly],
                                           [v for _, v in hourly])
        last = hourly[-1][0]
        forecast = []
        for step in range(1, BANDWIDTH_HORIZON_HOURS + 1):
            ts = last + timedelta(hours=step)
            yhat = slope * (ts - origin).total_seconds() / 3600 + intercept
            forecast.append((ts, yhat, yhat - 1.28 * spread, yhat + 1.28 * spread))
    limit = capacity * WARN_FRACTION if capacity else None
    busy_from = next((ts.isoformat() for ts, y, _lo, _hi in forecast if limit and y >= limit),
                     None)
    peak = max(forecast, key=lambda f: f[1])
    high = capacity or float("inf")
    series = [{"ts": ts.isoformat(), "yhat": round(_clip(y, high)), "lo": round(_clip(lo, high)),
               "hi": round(_clip(hi, high))} for ts, y, lo, hi in forecast]
    return base | {"status": "busy" if busy_from else "ok", "method": method,
                   "peak_bps": round(_clip(peak[1], high)), "peak_at": peak[0].isoformat(),
                   "busy_from": busy_from, "series": series}
