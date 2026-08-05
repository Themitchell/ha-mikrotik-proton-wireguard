"""Tests for staggered WireGuard refresh helpers."""

from __future__ import annotations

import pytest

from proton_mikrotik_wg.wg_credentials import WireGuardCredential
from proton_mikrotik_wg.wg_refresh import (
    WG_REFRESH_DAILY,
    WG_REFRESH_MONTHLY,
    WG_REFRESH_WEEKLY,
    advance_last_refresh,
    interval_seconds,
    missed_windows,
    oldest_slots,
)


def _cred(*, expiration_time: int, serial: str = "sn") -> WireGuardCredential:
    return WireGuardCredential(
        device_name="ha-wg-proton-1-x",
        serial_number=serial,
        client_private_key="sk==",
        client_public_key="pk==",
        server_public_key="spk==",
        endpoint_host="1.1.1.1",
        endpoint_port=51820,
        client_address="10.2.0.2/32",
        expiration_time=expiration_time,
    )


def test_interval_seconds_for_cadences():
    assert interval_seconds(WG_REFRESH_DAILY) == 86400
    assert interval_seconds(WG_REFRESH_WEEKLY) == 604800
    assert interval_seconds(WG_REFRESH_MONTHLY) == 30 * 86400


def test_interval_seconds_rejects_unknown_cadence():
    with pytest.raises(ValueError, match="cadence"):
        interval_seconds("yearly")


def test_missed_windows_zero_when_within_interval():
    assert missed_windows(now=1000, last_at=900, interval=200, cap=7) == 0


def test_missed_windows_counts_full_periods_and_caps():
    assert missed_windows(now=1000, last_at=100, interval=200, cap=7) == 4
    assert missed_windows(now=10_000, last_at=100, interval=200, cap=3) == 3


def test_missed_windows_zero_when_last_at_in_future():
    assert missed_windows(now=100, last_at=200, interval=50, cap=7) == 0


def test_oldest_slots_by_expiration_then_slot_number():
    slots = {
        1: _cred(expiration_time=300, serial="a"),
        2: _cred(expiration_time=100, serial="b"),
        3: _cred(expiration_time=100, serial="c"),
        4: _cred(expiration_time=200, serial="d"),
    }
    assert oldest_slots(slots, count=3) == [2, 3, 4]


def test_oldest_slots_count_zero_or_empty():
    assert oldest_slots({}, count=2) == []
    assert oldest_slots({1: _cred(expiration_time=1)}, count=0) == []


def test_advance_last_refresh_by_n_intervals():
    assert advance_last_refresh(last_at=100, interval=50, n=3) == 250


def test_missed_windows_rejects_bad_interval_or_cap():
    with pytest.raises(ValueError, match="interval"):
        missed_windows(now=10, last_at=0, interval=0, cap=1)
    with pytest.raises(ValueError, match="cap"):
        missed_windows(now=10, last_at=0, interval=1, cap=-1)


def test_advance_last_refresh_rejects_bad_args():
    with pytest.raises(ValueError, match="n"):
        advance_last_refresh(last_at=1, interval=1, n=-1)
    with pytest.raises(ValueError, match="interval"):
        advance_last_refresh(last_at=1, interval=0, n=1)
