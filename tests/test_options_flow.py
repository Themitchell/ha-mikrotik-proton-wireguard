"""Tests for MikroTik options flow."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from proton_mikrotik_wg.config_flow import (
    ProtonMikroTikWgConfigFlow,
    ProtonMikroTikWgOptionsFlow,
)
from proton_mikrotik_wg.const import (
    CONF_MIKROTIK_HOST,
    CONF_MIKROTIK_PASSWORD,
    CONF_MIKROTIK_PORT,
    CONF_MIKROTIK_USERNAME,
    CONF_MIKROTIK_USE_SSL,
    CONF_MIKROTIK_WAN_GATEWAY,
    CONF_TUNNEL_COUNT,
)
from proton_mikrotik_wg.mikrotik_client import (
    CannotConnectMikroTik,
    InvalidMikroTikAuth,
)


@pytest.fixture
def options_flow(hass):
    entry = SimpleNamespace(options={})
    flow = ProtonMikroTikWgOptionsFlow()
    flow.hass = hass
    # HA injects the entry; do not assign the read-only config_entry property.
    flow._config_entry = entry
    return flow


def test_async_get_options_flow_returns_handler_without_setting_config_entry():
    entry = SimpleNamespace(options={})
    handler = ProtonMikroTikWgConfigFlow.async_get_options_flow(entry)
    assert isinstance(handler, ProtonMikroTikWgOptionsFlow)
    with pytest.raises(AttributeError, match="no setter"):
        handler.config_entry = entry


@pytest.mark.asyncio
async def test_options_step_shows_form(options_flow):
    result = await options_flow.async_step_init()
    assert result["type"] == "form"
    assert result["step_id"] == "init"


@pytest.mark.asyncio
async def test_options_step_saves_on_successful_connect(options_flow):
    with patch(
        "proton_mikrotik_wg.config_flow.check_mikrotik_connection"
    ) as check:
        result = await options_flow.async_step_init(
            {
                CONF_MIKROTIK_HOST: "mikrotik.lan",
                CONF_MIKROTIK_USERNAME: "admin",
                CONF_MIKROTIK_PASSWORD: "secret",
                CONF_MIKROTIK_PORT: 8729,
                CONF_MIKROTIK_USE_SSL: True,
                CONF_MIKROTIK_WAN_GATEWAY: "192.0.2.1",
                CONF_TUNNEL_COUNT: 5,
            }
        )
    assert result["type"] == "create_entry"
    assert result["data"][CONF_MIKROTIK_HOST] == "mikrotik.lan"
    assert result["data"][CONF_MIKROTIK_WAN_GATEWAY] == "192.0.2.1"
    assert result["data"][CONF_TUNNEL_COUNT] == 5
    check.assert_called_once()


@pytest.mark.asyncio
async def test_options_step_invalid_auth(options_flow):
    with patch(
        "proton_mikrotik_wg.config_flow.check_mikrotik_connection",
        side_effect=InvalidMikroTikAuth("bad"),
    ):
        result = await options_flow.async_step_init(
            {
                CONF_MIKROTIK_HOST: "mikrotik.lan",
                CONF_MIKROTIK_USERNAME: "admin",
                CONF_MIKROTIK_PASSWORD: "bad",
                CONF_MIKROTIK_PORT: 8729,
                CONF_MIKROTIK_USE_SSL: True,
                CONF_MIKROTIK_WAN_GATEWAY: "192.0.2.1",
            }
        )
    assert result["errors"]["base"] == "invalid_auth"


@pytest.mark.asyncio
async def test_options_step_cannot_connect(options_flow):
    with patch(
        "proton_mikrotik_wg.config_flow.check_mikrotik_connection",
        side_effect=CannotConnectMikroTik("down"),
    ):
        result = await options_flow.async_step_init(
            {
                CONF_MIKROTIK_HOST: "mikrotik.lan",
                CONF_MIKROTIK_USERNAME: "admin",
                CONF_MIKROTIK_PASSWORD: "secret",
                CONF_MIKROTIK_PORT: 8729,
                CONF_MIKROTIK_USE_SSL: True,
                CONF_MIKROTIK_WAN_GATEWAY: "192.0.2.1",
            }
        )
    assert result["errors"]["base"] == "cannot_connect"


@pytest.mark.asyncio
async def test_options_step_unknown_error(options_flow):
    with patch(
        "proton_mikrotik_wg.config_flow.check_mikrotik_connection",
        side_effect=RuntimeError("boom"),
    ):
        result = await options_flow.async_step_init(
            {
                CONF_MIKROTIK_HOST: "mikrotik.lan",
                CONF_MIKROTIK_USERNAME: "admin",
                CONF_MIKROTIK_PASSWORD: "secret",
                CONF_MIKROTIK_PORT: 8729,
                CONF_MIKROTIK_USE_SSL: True,
                CONF_MIKROTIK_WAN_GATEWAY: "192.0.2.1",
            }
        )
    assert result["errors"]["base"] == "unknown"
