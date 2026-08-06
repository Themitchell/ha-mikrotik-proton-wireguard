"""Config-flow form schemas (no Home Assistant imports)."""

from __future__ import annotations

import voluptuous as vol

from .const import (
    CONF_MIKROTIK_HOST,
    CONF_MIKROTIK_PASSWORD,
    CONF_MIKROTIK_PORT,
    CONF_MIKROTIK_USERNAME,
    CONF_MIKROTIK_USE_SSL,
    CONF_MIKROTIK_WAN_GATEWAY,
    CONF_PASSWORD,
    CONF_TOTP,
    CONF_TUNNEL_COUNT,
    CONF_USERNAME,
    CONF_VPN_BYPASS_CIDRS,
    CONF_VPN_EXIT_COUNTRY,
    CONF_WG_REFRESH_INTERVAL,
    DEFAULT_MIKROTIK_PORT,
    DEFAULT_MIKROTIK_USE_SSL,
    DEFAULT_TUNNEL_COUNT,
    DEFAULT_WG_REFRESH_INTERVAL,
    MAX_TUNNEL_COUNT,
    MIN_TUNNEL_COUNT,
    VPN_EXIT_COUNTRY_ANY,
    WG_REFRESH_INTERVALS,
)
from .vpn_bypass import parse_vpn_bypass_cidrs


def _vpn_bypass_cidrs(value: object) -> str:
    text = "" if value is None else str(value)
    try:
        parse_vpn_bypass_cidrs(text)
    except ValueError as err:
        raise vol.Invalid(str(err)) from err
    return text


PROTON_CREDENTIALS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)

PROTON_REAUTH_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PASSWORD): str,
    }
)

PROTON_TWO_FACTOR_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_TOTP): str,
    }
)


def mikrotik_options_schema(
    defaults: dict | None = None,
    *,
    exit_countries: list[str] | None = None,
) -> vol.Schema:
    """Build the MikroTik options form, optionally prefilled from existing options."""
    current = defaults or {}
    countries = list(exit_countries or [])
    saved = str(current.get(CONF_VPN_EXIT_COUNTRY, VPN_EXIT_COUNTRY_ANY) or VPN_EXIT_COUNTRY_ANY)
    choices = [VPN_EXIT_COUNTRY_ANY]
    for code in countries:
        upper = code.upper()
        if upper and upper not in choices:
            choices.append(upper)
    if saved not in choices:
        choices.append(saved.upper() if saved != VPN_EXIT_COUNTRY_ANY else VPN_EXIT_COUNTRY_ANY)

    return vol.Schema(
        {
            vol.Required(
                CONF_MIKROTIK_HOST, default=current.get(CONF_MIKROTIK_HOST, "")
            ): str,
            vol.Required(
                CONF_MIKROTIK_USERNAME,
                default=current.get(CONF_MIKROTIK_USERNAME, ""),
            ): str,
            vol.Required(CONF_MIKROTIK_PASSWORD): str,
            vol.Required(
                CONF_MIKROTIK_PORT,
                default=current.get(CONF_MIKROTIK_PORT, DEFAULT_MIKROTIK_PORT),
            ): int,
            vol.Required(
                CONF_MIKROTIK_USE_SSL,
                default=current.get(CONF_MIKROTIK_USE_SSL, DEFAULT_MIKROTIK_USE_SSL),
            ): bool,
            vol.Required(
                CONF_MIKROTIK_WAN_GATEWAY,
                default=current.get(CONF_MIKROTIK_WAN_GATEWAY, ""),
            ): str,
            vol.Required(
                CONF_TUNNEL_COUNT,
                default=current.get(CONF_TUNNEL_COUNT, DEFAULT_TUNNEL_COUNT),
            ): vol.All(
                vol.Coerce(int), vol.Range(min=MIN_TUNNEL_COUNT, max=MAX_TUNNEL_COUNT)
            ),
            vol.Required(
                CONF_VPN_EXIT_COUNTRY,
                default=saved if saved in choices else VPN_EXIT_COUNTRY_ANY,
            ): vol.In(choices),
            vol.Required(
                CONF_WG_REFRESH_INTERVAL,
                default=current.get(
                    CONF_WG_REFRESH_INTERVAL, DEFAULT_WG_REFRESH_INTERVAL
                ),
            ): vol.In(list(WG_REFRESH_INTERVALS)),
            vol.Optional(
                CONF_VPN_BYPASS_CIDRS,
                default=current.get(CONF_VPN_BYPASS_CIDRS, ""),
            ): _vpn_bypass_cidrs,
        }
    )
