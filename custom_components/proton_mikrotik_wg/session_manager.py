"""Manage a live Proton API session inside Home Assistant."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any, Callable

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.event import async_track_time_interval

from .const import (
    CONF_MIKROTIK_HOST,
    CONF_MIKROTIK_PASSWORD,
    CONF_MIKROTIK_PORT,
    CONF_MIKROTIK_USERNAME,
    CONF_MIKROTIK_USE_SSL,
    CONF_MIKROTIK_WAN_GATEWAY,
    CONF_WG_CLIENT_ADDRESS,
    CONF_WG_CLIENT_PRIVATE_KEY,
    CONF_WG_CLIENT_PUBLIC_KEY,
    CONF_WG_DEVICE_NAME,
    CONF_WG_ENDPOINT_HOST,
    CONF_WG_ENDPOINT_PORT,
    CONF_WG_EXPIRATION_TIME,
    CONF_WG_SERIAL_NUMBER,
    CONF_WG_SERVER_PUBLIC_KEY,
    DEFAULT_MIKROTIK_PORT,
    DEFAULT_MIKROTIK_USE_SSL,
    DEFAULT_WG_DEVICE_NAME,
)
from .mikrotik_client import open_mikrotik_api
from .mikrotik_wg import (
    LibRouterOsClient,
    apply_tunnel_only,
    wireguard_credential_from_entry_data,
)
from .proton_auth import InvalidCredentials, ProtonAuthClient, ProtonSessionData
from .session_store import entry_data_from_session, session_data_from_entry
from .wg_credentials import WireGuardCredential, provision_wireguard_credential

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

        merged = dict(self.entry.data)
        merged.update(entry_data_from_session(updated))
        self.hass.config_entries.async_update_entry(self.entry, data=merged)
        return updated

    async def async_provision_wireguard(
        self, *, device_name: str = DEFAULT_WG_DEVICE_NAME
    ) -> WireGuardCredential:
        """Create one Proton WireGuard certificate labeled for Home Assistant."""
        if not device_name.startswith("ha-"):
            raise ValueError("device_name must start with 'ha-'")

        session = self._client.live_session()
        cred = await self.hass.async_add_executor_job(
            lambda: provision_wireguard_credential(
                session, device_name=device_name
            )
        )
        merged = dict(self.entry.data)
        merged.update(entry_data_from_session(self._client.data))
        merged.update(
            {
                CONF_WG_DEVICE_NAME: cred.device_name,
                CONF_WG_SERIAL_NUMBER: cred.serial_number,
                CONF_WG_CLIENT_PRIVATE_KEY: cred.client_private_key,
                CONF_WG_CLIENT_PUBLIC_KEY: cred.client_public_key,
                CONF_WG_SERVER_PUBLIC_KEY: cred.server_public_key,
                CONF_WG_ENDPOINT_HOST: cred.endpoint_host,
                CONF_WG_ENDPOINT_PORT: cred.endpoint_port,
                CONF_WG_CLIENT_ADDRESS: cred.client_address,
                CONF_WG_EXPIRATION_TIME: cred.expiration_time,
            }
        )
        self.hass.config_entries.async_update_entry(self.entry, data=merged)
        return cred

    async def async_apply_wireguard(self) -> WireGuardCredential:
        """Push the stored credential onto MikroTik as a tunnel-only config."""
        options = dict(self.entry.options)
        required = (
            CONF_MIKROTIK_HOST,
            CONF_MIKROTIK_USERNAME,
            CONF_MIKROTIK_PASSWORD,
            CONF_MIKROTIK_WAN_GATEWAY,
        )
        missing = [key for key in required if not options.get(key)]
        if missing:
            raise ValueError(
                "MikroTik is not configured — use Configure on the integration "
                f"(missing {', '.join(missing)})"
            )

        cred = wireguard_credential_from_entry_data(self.entry.data)
        wan_gateway = str(options[CONF_MIKROTIK_WAN_GATEWAY])

        def _apply() -> None:
            api = open_mikrotik_api(
                host=str(options[CONF_MIKROTIK_HOST]),
                username=str(options[CONF_MIKROTIK_USERNAME]),
                password=str(options[CONF_MIKROTIK_PASSWORD]),
                port=int(options.get(CONF_MIKROTIK_PORT, DEFAULT_MIKROTIK_PORT)),
                use_ssl=bool(
                    options.get(CONF_MIKROTIK_USE_SSL, DEFAULT_MIKROTIK_USE_SSL)
                ),
            )
            client = LibRouterOsClient(api)
            try:
                apply_tunnel_only(client, cred, wan_gateway=wan_gateway)
            finally:
                client.close()

        await self.hass.async_add_executor_job(_apply)
        return cred
