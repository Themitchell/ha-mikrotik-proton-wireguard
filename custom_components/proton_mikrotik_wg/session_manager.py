"""Manage a live Proton API session inside Home Assistant."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any, Callable

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.event import async_track_time_interval

from .const import (
    CONF_EGRESS_ENABLED,
    CONF_MIKROTIK_HOST,
    CONF_MIKROTIK_PASSWORD,
    CONF_MIKROTIK_PORT,
    CONF_MIKROTIK_USERNAME,
    CONF_MIKROTIK_USE_SSL,
    CONF_MIKROTIK_WAN_GATEWAY,
    CONF_TUNNEL_COUNT,
    DEFAULT_MIKROTIK_PORT,
    DEFAULT_MIKROTIK_USE_SSL,
    DEFAULT_TUNNEL_COUNT,
)
from .mikrotik_client import open_mikrotik_api
from .mikrotik_wg import (
    LibRouterOsClient,
    apply_wireguard_slots,
    disable_egress,
    enable_egress,
    is_egress_enabled,
)
from .proton_auth import InvalidCredentials, ProtonAuthClient, ProtonSessionData
from .session_store import entry_data_from_session, session_data_from_entry
from .wg_credentials import WireGuardCredential, provision_wireguard_slots
from .wg_slots import entry_data_from_slots, slots_from_entry_data

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

    def tunnel_count(self) -> int:
        """Configured simultaneous tunnel count (1–20)."""
        return int(self.entry.options.get(CONF_TUNNEL_COUNT, DEFAULT_TUNNEL_COUNT))

    async def async_setup(self) -> None:
        """Refresh once on startup and schedule periodic refresh."""
        await self.async_refresh()
        self._unsub = async_track_time_interval(
            self.hass, self._async_scheduled_refresh, self.refresh_interval
        )
        if self.entry.options.get(CONF_EGRESS_ENABLED) and self._mikrotik_configured():
            await self.async_set_egress(True)

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

    def _mikrotik_configured(self) -> bool:
        options = self.entry.options
        return all(
            options.get(key)
            for key in (
                CONF_MIKROTIK_HOST,
                CONF_MIKROTIK_USERNAME,
                CONF_MIKROTIK_PASSWORD,
                CONF_MIKROTIK_WAN_GATEWAY,
            )
        )

    def _require_mikrotik_options(self) -> dict[str, Any]:
        options = dict(self.entry.options)
        if not self._mikrotik_configured():
            raise ValueError(
                "MikroTik is not configured — use Configure on the integration"
            )
        return options

    def _open_mikrotik(self, options: dict[str, Any]) -> LibRouterOsClient:
        api = open_mikrotik_api(
            host=str(options[CONF_MIKROTIK_HOST]),
            username=str(options[CONF_MIKROTIK_USERNAME]),
            password=str(options[CONF_MIKROTIK_PASSWORD]),
            port=int(options.get(CONF_MIKROTIK_PORT, DEFAULT_MIKROTIK_PORT)),
            use_ssl=bool(options.get(CONF_MIKROTIK_USE_SSL, DEFAULT_MIKROTIK_USE_SSL)),
        )
        return LibRouterOsClient(api)

    def _require_slots(self) -> dict[int, WireGuardCredential]:
        slots = slots_from_entry_data(self.entry.data)
        if not slots:
            raise ValueError(
                "WireGuard credential is not provisioned on this entry"
            )
        return slots

    async def async_provision_wireguard(
        self, *, slot: int | None = None
    ) -> dict[int, WireGuardCredential]:
        """Provision all tunnels (or one slot) and store credentials on the entry."""
        count = self.tunnel_count()
        existing = slots_from_entry_data(self.entry.data)
        session = self._client.live_session()
        slots = await self.hass.async_add_executor_job(
            lambda: provision_wireguard_slots(
                session,
                count=count,
                existing=existing,
                slot=slot,
            )
        )
        merged = dict(self.entry.data)
        # Drop legacy flat WG keys when rewriting slots.
        for key in list(merged):
            if key.startswith("wg_") and key != "wg_slots":
                merged.pop(key, None)
        merged.update(entry_data_from_session(self._client.data))
        merged.update(entry_data_from_slots(slots))
        self.hass.config_entries.async_update_entry(self.entry, data=merged)
        return slots

    async def async_apply_wireguard(self) -> dict[int, WireGuardCredential]:
        """Push stored slot credentials onto MikroTik as tunnel-only configs."""
        options = self._require_mikrotik_options()
        slots = self._require_slots()
        wan_gateway = str(options[CONF_MIKROTIK_WAN_GATEWAY])
        count = self.tunnel_count()

        def _apply() -> None:
            client = self._open_mikrotik(options)
            try:
                apply_wireguard_slots(
                    client,
                    slots,
                    wan_gateway=wan_gateway,
                    tunnel_count=count,
                )
            finally:
                client.close()

        await self.hass.async_add_executor_job(_apply)
        return {s: c for s, c in slots.items() if s <= count}

    async def async_get_egress_enabled(self) -> bool:
        """Read whether whole-home VPN egress is currently enabled on the router."""
        options = self._require_mikrotik_options()

        def _read() -> bool:
            client = self._open_mikrotik(options)
            try:
                return is_egress_enabled(client)
            finally:
                client.close()

        return await self.hass.async_add_executor_job(_read)

    async def async_set_egress(self, enabled: bool) -> None:
        """Enable or disable ECMP whole-home VPN egress on the router."""
        options = self._require_mikrotik_options()
        wan_interface = str(options[CONF_MIKROTIK_WAN_GATEWAY])
        slots = self._require_slots() if enabled else {}
        count = self.tunnel_count()
        active = {s: c for s, c in slots.items() if s <= count}

        def _set() -> None:
            client = self._open_mikrotik(options)
            try:
                if enabled:
                    enable_egress(client, wan_interface=wan_interface, slots=active)
                else:
                    disable_egress(client, wan_interface=wan_interface)
            finally:
                client.close()

        await self.hass.async_add_executor_job(_set)
        merged = dict(self.entry.options)
        merged[CONF_EGRESS_ENABLED] = enabled
        self.hass.config_entries.async_update_entry(self.entry, options=merged)
