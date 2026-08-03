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
    CONF_USERNAME,
    DEFAULT_MIKROTIK_PORT,
    DEFAULT_MIKROTIK_USE_SSL,
)

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


def mikrotik_options_schema(defaults: dict | None = None) -> vol.Schema:
    """Build the MikroTik options form, optionally prefilled from existing options."""
    current = defaults or {}
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
        }
    )
