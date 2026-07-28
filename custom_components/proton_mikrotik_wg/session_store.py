"""Build ProtonSessionData from a Home Assistant config entry dict."""

from __future__ import annotations

from typing import Any, Mapping

from .const import (
    CONF_ACCESS_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_SCOPE,
    CONF_UID,
    CONF_USERNAME,
)
from .proton_auth import ProtonSessionData


def session_data_from_entry(data: Mapping[str, Any]) -> ProtonSessionData:
    """Rehydrate stored tokens from config entry data."""
    scope = data.get(CONF_SCOPE) or []
    return ProtonSessionData(
        username=data[CONF_USERNAME],
        uid=data[CONF_UID],
        access_token=data[CONF_ACCESS_TOKEN],
        refresh_token=data[CONF_REFRESH_TOKEN],
        scope=tuple(scope),
    )
