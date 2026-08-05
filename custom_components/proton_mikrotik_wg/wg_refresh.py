"""Helpers for staggered WireGuard credential refresh scheduling."""

from __future__ import annotations

from typing import Mapping

from .const import (
    WG_REFRESH_DAILY,
    WG_REFRESH_MONTHLY,
    WG_REFRESH_WEEKLY,
)
from .wg_credentials import WireGuardCredential

# Re-export cadence labels for callers/tests.
__all__ = [
    "WG_REFRESH_DAILY",
    "WG_REFRESH_WEEKLY",
    "WG_REFRESH_MONTHLY",
    "interval_seconds",
    "missed_windows",
    "oldest_slots",
    "advance_last_refresh",
]

_INTERVAL_SECONDS = {
    WG_REFRESH_DAILY: 86400,
    WG_REFRESH_WEEKLY: 604800,
    WG_REFRESH_MONTHLY: 30 * 86400,
}


def interval_seconds(cadence: str) -> int:
    """Return fixed interval length in seconds for a refresh cadence."""
    try:
        return _INTERVAL_SECONDS[cadence]
    except KeyError as err:
        raise ValueError(f"unknown refresh cadence: {cadence!r}") from err


def missed_windows(*, now: int, last_at: int, interval: int, cap: int) -> int:
    """How many full refresh periods elapsed since ``last_at``, capped at ``cap``."""
    if interval < 1:
        raise ValueError("interval must be at least 1")
    if cap < 0:
        raise ValueError("cap must be non-negative")
    if now <= last_at:
        return 0
    return min(cap, (now - last_at) // interval)


def oldest_slots(
    slots: Mapping[int, WireGuardCredential], *, count: int
) -> list[int]:
    """Return up to ``count`` slot numbers ordered oldest-first by expiration."""
    if count < 1 or not slots:
        return []
    ordered = sorted(
        slots.items(),
        key=lambda item: (item[1].expiration_time, item[0]),
    )
    return [slot for slot, _ in ordered[:count]]


def advance_last_refresh(*, last_at: int, interval: int, n: int) -> int:
    """Advance the schedule stamp by ``n`` intervals (preserves cadence phase)."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if interval < 1:
        raise ValueError("interval must be at least 1")
    return last_at + n * interval
