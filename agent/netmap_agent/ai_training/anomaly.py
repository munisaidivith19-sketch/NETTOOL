"""Unusual traffic on an interface, found with an Isolation Forest.

An Isolation Forest builds many random decision trees that split the data at random values.
Normal points sit in dense clusters and need many splits to be separated; a strange point
(a sudden 12× traffic burst at 3 a.m., a flood of errors) is isolated after very few splits.
That "how easy was it to isolate" is its anomaly score. No labelled examples are needed: the
model learns what normal looks like from the last week of this interface's own traffic.

The model says *that* a point is odd; the explanation (which value, compared with what is
usual for that hour) is computed separately so a person can check it.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

MIN_TRAINING_POINTS = 288  # about one day at a 5-minute poll interval
RECENT_SECONDS = 2 * 3600
CONTAMINATION = 0.01
MIN_RATIO = 3.0  # also require the value to be at least 3× off the usual for that hour
MIN_DELTA_BPS = 1_000_000  # ...and at least 1 Mbit/s different, so tiny links stay quiet


def _features(point: list) -> list[float]:
    ts, in_bps, out_bps, errors_per_s = point[:4]
    hour = datetime.fromtimestamp(int(ts), timezone.utc).hour
    angle = 2 * math.pi * hour / 24
    return [math.log1p(max(in_bps or 0, 0)), math.log1p(max(out_bps or 0, 0)),
            math.log1p(max(errors_per_s or 0, 0)) * 3, math.sin(angle), math.cos(angle)]


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    k = (len(ordered) - 1) * q
    low, high = math.floor(k), math.ceil(k)
    return ordered[low] + (ordered[high] - ordered[low]) * (k - low)


def _mbit(bps: float) -> str:
    return f"{bps / 1e6:.1f} Mbit/s" if bps >= 100_000 else f"{bps / 1e3:.0f} kbit/s"


def _explain(point: list, training: list[list], label: str) -> tuple[str, str, float, float]:
    """Pick the metric furthest from its usual range for that hour; return (metric, text,
    value, typical)."""
    ts = int(point[0])
    hour = datetime.fromtimestamp(ts, timezone.utc).hour
    same_hour = [p for p in training
                 if datetime.fromtimestamp(int(p[0]), timezone.utc).hour == hour]
    sample = same_hour if len(same_hour) >= 6 else training
    best = None
    for column, name in ((1, "Inbound traffic"), (2, "Outbound traffic"), (3, "Errors")):
        values = [float(p[column] or 0) for p in sample]
        median = _percentile(values, 0.5)
        value = float(point[column] or 0)
        low, high = _percentile(values, 0.05), _percentile(values, 0.95)
        ratio = (value + 1) / (median + 1)
        strength = max(ratio, 1 / ratio)
        if best is None or strength > best[0]:
            best = (strength, column, name, value, median, low, high)
    _strength, column, name, value, median, low, high = best
    when = datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M UTC")
    if column == 3:
        text = (f"{name} on {label}: {value:.1f}/s at {when}; usually {median:.1f}/s "
                f"(normally {low:.1f}–{high:.1f}/s at this hour).")
        metric = "errors"
    else:
        factor = (value + 1) / (median + 1)
        how = (f"about {factor:.0f}× the usual" if factor >= 1
               else f"about {1 / factor:.0f}× below the usual")
        text = (f"{name} on {label} was {_mbit(value)} at {when}, {how} {_mbit(median)} for this "
                f"hour (normally {_mbit(low)}–{_mbit(high)}).")
        metric = "in_bps" if column == 1 else "out_bps"
    return metric, text, value, median


def detect(points: list[list], label: str, now: datetime | None = None) -> dict:
    """points: [[epoch, in_bps, out_bps, errors_per_s]], oldest first.

    Returns {"checked": bool, "anomaly": None | {...}}. "checked" is False when there is not
    enough history to judge (the caller then leaves any existing alert alone).
    """
    import numpy as np
    from sklearn.ensemble import IsolationForest

    now_ts = (now or datetime.now(timezone.utc)).timestamp()
    clean = [p for p in points if p[1] is not None or p[2] is not None]
    training = [p for p in clean if p[0] < now_ts - RECENT_SECONDS]
    recent = [p for p in clean if p[0] >= now_ts - RECENT_SECONDS]
    if len(training) < MIN_TRAINING_POINTS or not recent:
        return {"checked": False, "anomaly": None}

    # Fit on the whole window, recent points included. Trees only split inside the range of
    # the data they were built from, so a spike left out of the fit would land in the same
    # leaf as the busiest normal hour and look ordinary. Inside the fit, a lone spike is
    # isolated after very few splits, which is exactly what the score measures.
    # max_samples=1.0: every tree sees every point (a week is only ~2000 points). With the
    # default 256-point samples a single error burst is missing from most trees, and where
    # it is missing the all-zero error column can't be split at all.
    model = IsolationForest(n_estimators=200, max_samples=1.0, contamination=CONTAMINATION,
                            random_state=42)
    model.fit(np.array([_features(p) for p in training + recent]))
    recent_x = np.array([_features(p) for p in recent])
    scores = model.decision_function(recent_x)
    flagged = model.predict(recent_x)
    worst = None
    for point, score, flag in zip(recent, scores, flagged, strict=True):
        if flag != -1:
            continue
        metric, text, value, typical = _explain(point, training, label)
        ratio = max((value + 1) / (typical + 1), (typical + 1) / (value + 1))
        big_enough = metric == "errors" and value >= 1 or (
            ratio >= MIN_RATIO and abs(value - typical) >= MIN_DELTA_BPS)
        if big_enough and (worst is None or score < worst["score"]):
            worst = {"ts": datetime.fromtimestamp(int(point[0]), timezone.utc).isoformat(),
                     "score": round(float(score), 4), "metric": metric, "value": round(value, 1),
                     "typical": round(typical, 1), "explanation": text}
    return {"checked": True, "anomaly": worst}
