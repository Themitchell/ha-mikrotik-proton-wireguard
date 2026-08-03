"""Reauth config-flow coverage."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from proton_mikrotik_wg.config_flow import ProtonMikroTikWgConfigFlow
from proton_mikrotik_wg.const import (
    CONF_ACCESS_TOKEN,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_USERNAME,
)
from proton_mikrotik_wg.proton_auth import ProtonSessionData


def _session_data(**overrides):
    base = ProtonSessionData(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-new",
        refresh_token="refresh-new",
        scope=("full", "self"),
    )
    return ProtonSessionData(**{**base.__dict__, **overrides})


@pytest.fixture
def flow(hass):
    instance = ProtonMikroTikWgConfigFlow()
    instance.hass = hass
    entry = SimpleNamespace(
        entry_id="entry-1",
        data={
            CONF_USERNAME: "user@proton.me",
            CONF_ACCESS_TOKEN: "access-old",
            CONF_REFRESH_TOKEN: "refresh-old",
        },
        title="Proton VPN (user@proton.me)",
    )
    hass.config_entries = SimpleNamespace(
        async_get_entry=MagicMock(return_value=entry),
        async_update_entry=MagicMock(),
        async_reload=MagicMock(),
    )
    instance.context = {"entry_id": "entry-1", "source": "reauth"}
    instance._reauth_entry = entry
    return instance


@pytest.mark.asyncio
async def test_reauth_step_shows_password_form(flow):
    result = await flow.async_step_reauth({"ignored": True})
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_confirm"
    assert result["errors"] == {}


@pytest.mark.asyncio
async def test_reauth_confirm_updates_entry_on_success(flow):
    session = _session_data()
    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        return_value=session,
    ):
        result = await flow.async_step_reauth_confirm({CONF_PASSWORD: "secret"})
    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    flow.hass.config_entries.async_update_entry.assert_called_once()
    _, kwargs = flow.hass.config_entries.async_update_entry.call_args
    assert kwargs["data"][CONF_ACCESS_TOKEN] == "access-new"
    assert kwargs["data"][CONF_REFRESH_TOKEN] == "refresh-new"
    assert CONF_PASSWORD not in kwargs["data"]


@pytest.mark.asyncio
async def test_reauth_confirm_invalid_password(flow):
    from proton_mikrotik_wg.proton_auth import InvalidCredentials

    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        side_effect=InvalidCredentials("bad"),
    ):
        result = await flow.async_step_reauth_confirm({CONF_PASSWORD: "bad"})
    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_auth"


@pytest.mark.asyncio
async def test_reauth_confirm_routes_to_two_factor(flow):
    from proton_mikrotik_wg.proton_auth import TwoFactorRequired
    from proton_mikrotik_wg.const import CONF_TOTP

    pending = MagicMock(name="pending-session")
    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        side_effect=TwoFactorRequired(pending, _session_data(scope=("twofactor",))),
    ):
        result = await flow.async_step_reauth_confirm({CONF_PASSWORD: "secret"})
    assert result["step_id"] == "two_factor"

    with patch(
        "proton_mikrotik_wg.config_flow.submit_two_factor",
        return_value=_session_data(),
    ):
        result = await flow.async_step_two_factor({CONF_TOTP: "123456"})
    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"


@pytest.mark.asyncio
async def test_reauth_confirm_cannot_connect(flow):
    from proton_mikrotik_wg.proton_auth import CannotConnect

    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        side_effect=CannotConnect("offline"),
    ):
        result = await flow.async_step_reauth_confirm({CONF_PASSWORD: "secret"})
    assert result["errors"]["base"] == "cannot_connect"


@pytest.mark.asyncio
async def test_reauth_confirm_unknown_error(flow):
    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        side_effect=RuntimeError("boom"),
    ):
        result = await flow.async_step_reauth_confirm({CONF_PASSWORD: "secret"})
    assert result["errors"]["base"] == "unknown"


@pytest.mark.asyncio
async def test_reauth_without_entry_id_uses_entry_data_username(hass):
    instance = ProtonMikroTikWgConfigFlow()
    instance.hass = hass
    instance.context = {}
    hass.config_entries = SimpleNamespace(
        async_get_entry=MagicMock(return_value=None),
        async_update_entry=MagicMock(),
    )
    result = await instance.async_step_reauth({CONF_USERNAME: "user@proton.me"})
    assert result["step_id"] == "reauth_confirm"
    assert instance._username == "user@proton.me"


@pytest.mark.asyncio
async def test_reauth_without_username_still_shows_form(hass):
    instance = ProtonMikroTikWgConfigFlow()
    instance.hass = hass
    instance.context = {}
    hass.config_entries = SimpleNamespace(
        async_get_entry=MagicMock(return_value=None),
        async_update_entry=MagicMock(),
    )
    result = await instance.async_step_reauth({})
    assert result["step_id"] == "reauth_confirm"
    assert instance._username is None
