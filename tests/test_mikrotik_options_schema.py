"""Tests for MikroTik options schema including tunnel_count and exit country."""

from __future__ import annotations

import pytest
import voluptuous as vol

from proton_mikrotik_wg.const import (
    CONF_MIKROTIK_HOST,
    CONF_MIKROTIK_PASSWORD,
    CONF_MIKROTIK_PORT,
    CONF_MIKROTIK_USERNAME,
    CONF_MIKROTIK_USE_SSL,
    CONF_MIKROTIK_WAN_GATEWAY,
    CONF_TUNNEL_COUNT,
    CONF_VPN_EXIT_COUNTRY,
    CONF_WG_REFRESH_INTERVAL,
    DEFAULT_TUNNEL_COUNT,
    DEFAULT_WG_REFRESH_INTERVAL,
    VPN_EXIT_COUNTRY_ANY,
    WG_REFRESH_WEEKLY,
)
from proton_mikrotik_wg.schemas import mikrotik_options_schema


def _base(**overrides):
    data = {
        CONF_MIKROTIK_HOST: "mikrotik.lan",
        CONF_MIKROTIK_USERNAME: "admin",
        CONF_MIKROTIK_PASSWORD: "secret",
        CONF_MIKROTIK_PORT: 8729,
        CONF_MIKROTIK_USE_SSL: True,
        CONF_MIKROTIK_WAN_GATEWAY: "zen",
    }
    data.update(overrides)
    return data


def test_mikrotik_options_schema_defaults_tunnel_count_and_any_country():
    parsed = mikrotik_options_schema()(_base())
    assert parsed[CONF_TUNNEL_COUNT] == DEFAULT_TUNNEL_COUNT
    assert parsed[CONF_VPN_EXIT_COUNTRY] == VPN_EXIT_COUNTRY_ANY
    assert parsed[CONF_WG_REFRESH_INTERVAL] == DEFAULT_WG_REFRESH_INTERVAL


def test_mikrotik_options_schema_accepts_refresh_cadence():
    parsed = mikrotik_options_schema()(
        _base(**{CONF_WG_REFRESH_INTERVAL: WG_REFRESH_WEEKLY})
    )
    assert parsed[CONF_WG_REFRESH_INTERVAL] == WG_REFRESH_WEEKLY


def test_mikrotik_options_schema_rejects_unknown_refresh_cadence():
    with pytest.raises(vol.Invalid):
        mikrotik_options_schema()(_base(**{CONF_WG_REFRESH_INTERVAL: "yearly"}))


def test_mikrotik_options_schema_accepts_fetched_exit_country():
    schema = mikrotik_options_schema(exit_countries=["NL", "GB"])
    parsed = schema(_base(**{CONF_VPN_EXIT_COUNTRY: "GB"}))
    assert parsed[CONF_VPN_EXIT_COUNTRY] == "GB"


def test_mikrotik_options_schema_rejects_unknown_exit_country():
    schema = mikrotik_options_schema(exit_countries=["GB"])
    with pytest.raises(vol.Invalid):
        schema(_base(**{CONF_VPN_EXIT_COUNTRY: "ZZ"}))


def test_mikrotik_options_schema_keeps_saved_country_if_fetch_empty():
    schema = mikrotik_options_schema(
        {CONF_VPN_EXIT_COUNTRY: "CH"},
        exit_countries=[],
    )
    parsed = schema(_base(**{CONF_VPN_EXIT_COUNTRY: "CH"}))
    assert parsed[CONF_VPN_EXIT_COUNTRY] == "CH"


def test_mikrotik_options_schema_skips_blank_exit_country_codes():
    schema = mikrotik_options_schema(exit_countries=["", "GB", "gb"])
    parsed = schema(_base(**{CONF_VPN_EXIT_COUNTRY: "GB"}))
    assert parsed[CONF_VPN_EXIT_COUNTRY] == "GB"


def test_mikrotik_options_schema_accepts_tunnel_count_1_to_20():
    assert (
        mikrotik_options_schema()(_base(**{CONF_TUNNEL_COUNT: 1}))[CONF_TUNNEL_COUNT]
        == 1
    )
    assert (
        mikrotik_options_schema()(_base(**{CONF_TUNNEL_COUNT: 20}))[CONF_TUNNEL_COUNT]
        == 20
    )


def test_mikrotik_options_schema_rejects_tunnel_count_out_of_range():
    with pytest.raises(vol.Invalid):
        mikrotik_options_schema()(_base(**{CONF_TUNNEL_COUNT: 0}))
    with pytest.raises(vol.Invalid):
        mikrotik_options_schema()(_base(**{CONF_TUNNEL_COUNT: 21}))
