"""Manage a live Proton API session inside Home Assistant."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any, Callable

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.event import async_track_time_interval

from .proton_auth import InvalidCredentials, ProtonAuthClient, ProtonSessionData
from .session_store import entry_data_from_session, session_data_from_entry

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

# Refresh well inside Proton's ~30 day session lifetime.
DEFAULT_REFRESH_INTERVAL = timedelta(hours=12)


class ProtonSessionManager:
    """Owns ProtonAuthClient, refreshes tokens, and persists them on the entry."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        *,
        client: ProtonAuthClient | None = None,
        refresh_interval: timedelta = DEFAULT_REFRESH_INTERVAL,
    ) -> None:
        self.hass = hass
        self.entry = entry
        self.refresh_interval = refresh_interval
        self._client = client or ProtonAuthClient(session_data_from_entry(entry.data))
        self._unsub: Callable[[], None] | None = None

    @property
    def client(self) -> ProtonAuthClient:
        return self._client

    @property
    def data(self) -> ProtonSessionData:
        return self._client.data

    async def async_setup(self) -> None:
        """Refresh once on startup and schedule periodic refresh."""
        await self.async_refresh()
        self._unsub = async_track_time_interval(
            self.hass, self._async_scheduled_refresh, self.refresh_interval
        )

    async def async_unload(self) -> None:
        """Cancel periodic refresh."""
        if self._unsub is not None:
            self._unsub()
            self._unsub = None

    async def _async_scheduled_refresh(self, _now: Any = None) -> None:
        await self.async_refresh()

    async def async_refresh(self) -> ProtonSessionData:
        """Refresh Proton tokens and write them back to the config entry."""
        try:
            updated = await self.hass.async_add_executor_job(self._client.refresh)
        except InvalidCredentials as err:
            raise ConfigEntryAuthFailed("Proton session refresh failed") from err

        self.hass.config_entries.async_update_entry(
            self.entry,
            data=entry_data_from_session(updated),
        )
        return updated
