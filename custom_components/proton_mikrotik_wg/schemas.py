"""Config-flow form schemas (no Home Assistant imports)."""

from __future__ import annotations

import voluptuous as vol

from .const import CONF_PASSWORD, CONF_USERNAME

PROTON_CREDENTIALS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)
