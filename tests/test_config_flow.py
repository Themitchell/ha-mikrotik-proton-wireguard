"""Config flow step coverage with Home Assistant stubs."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from proton_mikrotik_wg.config_flow import ProtonMikroTikWgConfigFlow
from proton_mikrotik_wg.const import (
    CONF_ACCESS_TOKEN,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_SCOPE,
    CONF_TOTP,
    CONF_UID,
    CONF_USERNAME,
)
from proton_mikrotik_wg.proton_auth import (
    CannotConnect,
    InvalidCredentials,
    ProtonSessionData,
    TwoFactorRequired,
)
from proton_mikrotik_wg.session_store import entry_data_from_session


def _session_data(**overrides):
    base = ProtonSessionData(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-1",
        refresh_token="refresh-1",
        scope=("full", "self"),
    )
    return ProtonSessionData(**{**base.__dict__, **overrides})


@pytest.fixture
def flow(hass):
    instance = ProtonMikroTikWgConfigFlow()
    instance.hass = hass
    return instance


def test_entry_data_maps_session_fields():
    data = entry_data_from_session(_session_data())
    assert data[CONF_USERNAME] == "user@proton.me"
    assert data[CONF_UID] == "uid-1"
    assert data[CONF_ACCESS_TOKEN] == "access-1"
    assert data[CONF_REFRESH_TOKEN] == "refresh-1"
    assert data[CONF_SCOPE] == ["full", "self"]


@pytest.mark.asyncio
async def test_user_step_shows_form_without_input(flow):
    result = await flow.async_step_user()
    assert result["type"] == "form"
    assert result["step_id"] == "user"
    assert result["errors"] == {}


@pytest.mark.asyncio
async def test_user_step_creates_entry_on_successful_login(flow):
    session = _session_data()
    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        return_value=session,
    ):
        result = await flow.async_step_user(
            {
                CONF_USERNAME: "user@proton.me",
                CONF_PASSWORD: "secret",
            }
        )
    assert result["type"] == "create_entry"
    assert result["title"] == "Proton VPN (user@proton.me)"
    assert result["data"][CONF_UID] == "uid-1"
    assert CONF_PASSWORD not in result["data"]
    assert flow.unique_id == "user@proton.me"


@pytest.mark.asyncio
async def test_user_step_normalizes_unique_id_case(flow):
    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        return_value=_session_data(username="User@Proton.me"),
    ):
        await flow.async_step_user(
            {CONF_USERNAME: "User@Proton.me", CONF_PASSWORD: "secret"}
        )
    assert flow.unique_id == "user@proton.me"


@pytest.mark.asyncio
async def test_user_step_invalid_credentials(flow):
    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        side_effect=InvalidCredentials("nope"),
    ):
        result = await flow.async_step_user(
            {CONF_USERNAME: "user@proton.me", CONF_PASSWORD: "bad"}
        )
    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_auth"


@pytest.mark.asyncio
async def test_user_step_cannot_connect(flow):
    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        side_effect=CannotConnect("offline"),
    ):
        result = await flow.async_step_user(
            {CONF_USERNAME: "user@proton.me", CONF_PASSWORD: "secret"}
        )
    assert result["type"] == "form"
    assert result["errors"]["base"] == "cannot_connect"


@pytest.mark.asyncio
async def test_user_step_unknown_error(flow):
    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        side_effect=RuntimeError("boom"),
    ):
        result = await flow.async_step_user(
            {CONF_USERNAME: "user@proton.me", CONF_PASSWORD: "secret"}
        )
    assert result["errors"]["base"] == "unknown"


@pytest.mark.asyncio
async def test_user_step_routes_to_two_factor(flow):
    pending = MagicMock(name="pending-session")
    with patch(
        "proton_mikrotik_wg.config_flow.login_with_password_failover",
        side_effect=TwoFactorRequired(pending, _session_data(scope=("twofactor",))),
    ):
        result = await flow.async_step_user(
            {CONF_USERNAME: "user@proton.me", CONF_PASSWORD: "secret"}
        )
    assert result["type"] == "form"
    assert result["step_id"] == "two_factor"
    assert flow._pending_session is pending
    assert flow._username == "user@proton.me"


@pytest.mark.asyncio
async def test_user_step_aborts_when_already_configured(flow):
    from ha_stubs import AbortFlow

    flow._abort_configured = True
    with pytest.raises(AbortFlow) as exc:
        await flow.async_step_user(
            {CONF_USERNAME: "user@proton.me", CONF_PASSWORD: "secret"}
        )
    assert exc.value.reason == "already_configured"


@pytest.mark.asyncio
async def test_two_factor_step_shows_form_without_input(flow):
    flow._username = "user@proton.me"
    flow._pending_session = MagicMock()
    result = await flow.async_step_two_factor()
    assert result["step_id"] == "two_factor"


@pytest.mark.asyncio
async def test_two_factor_step_creates_entry(flow):
    flow._username = "user@proton.me"
    flow._pending_session = MagicMock()
    with patch(
        "proton_mikrotik_wg.config_flow.submit_two_factor",
        return_value=_session_data(),
    ):
        result = await flow.async_step_two_factor({CONF_TOTP: "123456"})
    assert result["type"] == "create_entry"
    assert result["data"][CONF_ACCESS_TOKEN] == "access-1"


@pytest.mark.asyncio
async def test_two_factor_step_invalid_code(flow):
    flow._username = "user@proton.me"
    flow._pending_session = MagicMock()
    with patch(
        "proton_mikrotik_wg.config_flow.submit_two_factor",
        side_effect=InvalidCredentials("bad"),
    ):
        result = await flow.async_step_two_factor({CONF_TOTP: "000000"})
    assert result["errors"]["base"] == "invalid_auth"


@pytest.mark.asyncio
async def test_two_factor_step_cannot_connect(flow):
    flow._username = "user@proton.me"
    flow._pending_session = MagicMock()
    with patch(
        "proton_mikrotik_wg.config_flow.submit_two_factor",
        side_effect=CannotConnect("offline"),
    ):
        result = await flow.async_step_two_factor({CONF_TOTP: "123456"})
    assert result["errors"]["base"] == "cannot_connect"


@pytest.mark.asyncio
async def test_two_factor_step_unknown_error(flow):
    flow._username = "user@proton.me"
    flow._pending_session = MagicMock()
    with patch(
        "proton_mikrotik_wg.config_flow.submit_two_factor",
        side_effect=RuntimeError("boom"),
    ):
        result = await flow.async_step_two_factor({CONF_TOTP: "123456"})
    assert result["errors"]["base"] == "unknown"
