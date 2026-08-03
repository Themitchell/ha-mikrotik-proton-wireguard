"""Tests for Proton API host failover on connect failures."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from proton_mikrotik_wg.proton_auth import (
    DEFAULT_API_URL,
    DEFAULT_API_URLS,
    CannotConnect,
    InvalidCredentials,
    ProtonSessionData,
    login_with_password_failover,
    session_factory_for_url,
)


def _session(**overrides):
    base = dict(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-1",
        refresh_token="refresh-1",
        scope=("full", "self"),
    )
    base.update(overrides)
    return ProtonSessionData(**base)


def test_default_api_prefers_legacy_protonvpn_host():
    assert DEFAULT_API_URL == "https://api.protonvpn.ch"
    assert DEFAULT_API_URLS[0] == DEFAULT_API_URL
    assert "https://vpn-api.proton.me" in DEFAULT_API_URLS


def test_failover_tries_next_host_after_cannot_connect():
    good = _session()
    with patch(
        "proton_mikrotik_wg.proton_auth.login_with_password",
        side_effect=[CannotConnect("blocked"), good],
    ) as login:
        assert login_with_password_failover("user@proton.me", "secret") is good
    assert login.call_count == 2


def test_failover_does_not_retry_invalid_credentials():
    with patch(
        "proton_mikrotik_wg.proton_auth.login_with_password",
        side_effect=InvalidCredentials("bad"),
    ) as login:
        with pytest.raises(InvalidCredentials):
            login_with_password_failover("user@proton.me", "bad")
    assert login.call_count == 1


def test_failover_raises_last_cannot_connect():
    with patch(
        "proton_mikrotik_wg.proton_auth.login_with_password",
        side_effect=CannotConnect("still offline"),
    ):
        with pytest.raises(CannotConnect, match="still offline"):
            login_with_password_failover("user@proton.me", "secret")


def test_session_factory_for_url_sets_api_url():
    with patch("proton_mikrotik_wg.proton_http.ProtonHttpSession") as cls:
        session_factory_for_url("https://api.protonvpn.ch")()
    assert cls.call_args.kwargs["api_url"] == "https://api.protonvpn.ch"
