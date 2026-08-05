"""Manage a live Proton API session inside Home Assistant."""

from __future__ import annotations

import logging
import time
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
    CONF_VPN_EXIT_COUNTRY,
    CONF_WG_REFRESH_INTERVAL,
    CONF_WG_REFRESH_LAST_AT,
    DEFAULT_MIKROTIK_PORT,
    DEFAULT_MIKROTIK_USE_SSL,
    DEFAULT_TUNNEL_COUNT,
    DEFAULT_WG_REFRESH_INTERVAL,
    VPN_EXIT_COUNTRY_ANY,
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
from .wg_refresh import (
    advance_last_refresh,
    interval_seconds,
    missed_windows,
    oldest_slots,
)
from .wg_slots import entry_data_from_slots, slots_from_entry_data

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

# Refresh well inside Proton's ~30 day session lifetime.
DEFAULT_REFRESH_INTERVAL = timedelta(hours=12)
DEFAULT_WG_REFRESH_CHECK_INTERVAL = timedelta(hours=1)


class ProtonSessionManager:
    """Owns ProtonAuthClient, refreshes tokens, and persists them on the entry."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        *,
        client: ProtonAuthClient | None = None,
        refresh_interval: timedelta = DEFAULT_REFRESH_INTERVAL,
        wg_refresh_check_interval: timedelta = DEFAULT_WG_REFRESH_CHECK_INTERVAL,
    ) -> None:
        self.hass = hass
        self.entry = entry
        self.refresh_interval = refresh_interval
        self.wg_refresh_check_interval = wg_refresh_check_interval
        self._client = client or ProtonAuthClient(session_data_from_entry(entry.data))
        self._unsub: Callable[[], None] | None = None
        self._unsub_wg: Callable[[], None] | None = None
        self._wg_refresh_running = False

    @property
    def client(self) -> ProtonAuthClient:
        return self._client

    @property
    def data(self) -> ProtonSessionData:
        return self._client.data

    def tunnel_count(self) -> int:
        """Configured simultaneous tunnel count (1–20)."""
        return int(self.entry.options.get(CONF_TUNNEL_COUNT, DEFAULT_TUNNEL_COUNT))

    def vpn_exit_country(self) -> str | None:
        """Configured Proton ExitCountry, or None for any region."""
        value = str(
            self.entry.options.get(CONF_VPN_EXIT_COUNTRY, VPN_EXIT_COUNTRY_ANY)
        ).strip()
        if not value or value.lower() == VPN_EXIT_COUNTRY_ANY:
            return None
        return value.upper()

    def wg_refresh_interval(self) -> str:
        """Configured staggered credential refresh cadence."""
        value = str(
            self.entry.options.get(
                CONF_WG_REFRESH_INTERVAL, DEFAULT_WG_REFRESH_INTERVAL
            )
        ).strip()
        return value or DEFAULT_WG_REFRESH_INTERVAL

    async def async_setup(self) -> None:
        """Refresh once on startup and schedule periodic refresh."""
        await self.async_refresh()
        self._unsub = async_track_time_interval(
            self.hass, self._async_scheduled_refresh, self.refresh_interval
        )
        self._unsub_wg = async_track_time_interval(
            self.hass,
            self._async_scheduled_wg_refresh,
            self.wg_refresh_check_interval,
        )
        await self._async_ensure_wg_refresh_stamp()
        await self.async_refresh_due_slots()
        if self.entry.options.get(CONF_EGRESS_ENABLED) and self._mikrotik_configured():
            await self.async_set_egress(True)

    async def async_unload(self) -> None:
        """Cancel periodic refresh."""
        if self._unsub is not None:
            self._unsub()
            self._unsub = None
        if self._unsub_wg is not None:
            self._unsub_wg()
            self._unsub_wg = None

    async def _async_scheduled_refresh(self, _now: Any = None) -> None:
        await self.async_refresh()

    async def _async_scheduled_wg_refresh(self, _now: Any = None) -> None:
        await self.async_refresh_due_slots()

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

    def _update_options(self, **updates: Any) -> None:
        merged = dict(self.entry.options)
        merged.update(updates)
        self.hass.config_entries.async_update_entry(self.entry, options=merged)
        # Unit-test stubs use a mutable options dict; keep it in sync when possible.
        options = self.entry.options
        if type(options) is dict:
            options.clear()
            options.update(merged)

    async def _async_ensure_wg_refresh_stamp(self) -> None:
        """Seed last_refresh_at when slots exist but stamp is missing (no mass renew)."""
        if CONF_WG_REFRESH_LAST_AT in self.entry.options:
            return
        if not slots_from_entry_data(self.entry.data):
            return
        self._update_options(**{CONF_WG_REFRESH_LAST_AT: int(time.time())})

    async def async_refresh_due_slots(self) -> int:
        """Renew N oldest slots for missed windows, then apply to MikroTik.

        Returns the number of slots renewed.
        """
        if self._wg_refresh_running:
            return 0
        if not self._mikrotik_configured():
            return 0
        slots = slots_from_entry_data(self.entry.data)
        if not slots:
            return 0
        last_at = self.entry.options.get(CONF_WG_REFRESH_LAST_AT)
        if last_at is None:
            return 0

        cadence = self.wg_refresh_interval()
        interval = interval_seconds(cadence)
        count = self.tunnel_count()
        due = missed_windows(
            now=int(time.time()),
            last_at=int(last_at),
            interval=interval,
            cap=count,
        )
        if due < 1:
            return 0

        targets = oldest_slots(slots, count=due)
        self._wg_refresh_running = True
        try:
            for slot in targets:
                await self.async_provision_wireguard(slot=slot)
            await self.async_apply_wireguard()
            new_last = advance_last_refresh(
                last_at=int(last_at), interval=interval, n=len(targets)
            )
            self._update_options(**{CONF_WG_REFRESH_LAST_AT: new_last})
            _LOGGER.info(
                "Renewed WireGuard slots %s (%s missed window(s)); applied to MikroTik",
                ", ".join(str(s) for s in targets),
                due,
            )
            return len(targets)
        except Exception:  # noqa: BLE001 — leave stamp unchanged; retry later
            _LOGGER.exception("Staggered WireGuard refresh failed; will retry later")
            return 0
        finally:
            self._wg_refresh_running = False

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
                exit_country=self.vpn_exit_country(),
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
        data = self.entry.data
        if type(data) is dict:
            data.clear()
            data.update(merged)
        if slot is None:
            self._update_options(**{CONF_WG_REFRESH_LAST_AT: int(time.time())})
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
        self._update_options(**{CONF_EGRESS_ENABLED: enabled})
