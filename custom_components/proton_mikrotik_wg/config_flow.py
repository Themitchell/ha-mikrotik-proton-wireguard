"""Config flow for Proton MikroTik WireGuard setup."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import CONF_PASSWORD, CONF_TOTP, CONF_USERNAME, DOMAIN
from .proton_auth import (
    CannotConnect,
    InvalidCredentials,
    ProtonSessionData,
    TwoFactorRequired,
    login_with_password_failover,
    submit_two_factor,
)
from .schemas import (
    PROTON_CREDENTIALS_SCHEMA,
    PROTON_REAUTH_SCHEMA,
    PROTON_TWO_FACTOR_SCHEMA,
)
from .session_store import entry_data_from_session

_LOGGER = logging.getLogger(__name__)


class ProtonMikroTikWgConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle Proton login (and 2FA) during integration setup."""

    VERSION = 1

    def __init__(self) -> None:
        super().__init__()
        self._username: str | None = None
        self._pending_session: Any = None
        self._reauth_entry: config_entries.ConfigEntry | None = None

    def _finish_login(self, username: str, session_data: ProtonSessionData) -> FlowResult:
        """Create a new entry, or update+reload during reauth."""
        data = entry_data_from_session(session_data)
        if self._reauth_entry is not None:
            return self.async_update_reload_and_abort(self._reauth_entry, data=data)
        return self.async_create_entry(
            title=f"Proton VPN ({username})",
            data=data,
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask for Proton account credentials and verify login."""
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]
            await self.async_set_unique_id(username.lower())
            self._abort_if_unique_id_configured()

            try:
                session_data = await self.hass.async_add_executor_job(
                    lambda: login_with_password_failover(username, password)
                )
            except TwoFactorRequired as err:
                self._username = username
                self._pending_session = err.session
                return await self.async_step_two_factor()
            except InvalidCredentials:
                errors["base"] = "invalid_auth"
            except CannotConnect as err:
                _LOGGER.warning("Proton connect failed: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected Proton login failure")
                errors["base"] = "unknown"
            else:
                return self._finish_login(username, session_data)

        return self.async_show_form(
            step_id="user",
            data_schema=PROTON_CREDENTIALS_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> FlowResult:
        """Start reauth when stored tokens can no longer be refreshed."""
        entry_id = self.context.get("entry_id")
        if entry_id:
            self._reauth_entry = self.hass.config_entries.async_get_entry(entry_id)
        if self._reauth_entry is not None:
            self._username = self._reauth_entry.data[CONF_USERNAME]
        elif CONF_USERNAME in entry_data:
            self._username = entry_data[CONF_USERNAME]
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask for Proton account password to renew the session."""
        errors: dict[str, str] = {}
        username = self._username
        if username is None and self._reauth_entry is not None:
            username = self._reauth_entry.data[CONF_USERNAME]
            self._username = username

        if user_input is not None and username is not None:
            password = user_input[CONF_PASSWORD]
            try:
                session_data = await self.hass.async_add_executor_job(
                    lambda: login_with_password_failover(username, password)
                )
            except TwoFactorRequired as err:
                self._pending_session = err.session
                return await self.async_step_two_factor()
            except InvalidCredentials:
                errors["base"] = "invalid_auth"
            except CannotConnect as err:
                _LOGGER.warning("Proton reauth connect failed: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected Proton reauth failure")
                errors["base"] = "unknown"
            else:
                return self._finish_login(username, session_data)

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=PROTON_REAUTH_SCHEMA,
            errors=errors,
        )

    async def async_step_two_factor(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask for TOTP after password authentication succeeds."""
        errors: dict[str, str] = {}

        if user_input is not None:
            assert self._pending_session is not None
            assert self._username is not None
            try:
                session_data = await self.hass.async_add_executor_job(
                    lambda: submit_two_factor(
                        self._pending_session,
                        user_input[CONF_TOTP],
                        username=self._username,
                    )
                )
            except InvalidCredentials:
                errors["base"] = "invalid_auth"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected Proton 2FA failure")
                errors["base"] = "unknown"
            else:
                return self._finish_login(self._username, session_data)

        return self.async_show_form(
            step_id="two_factor",
            data_schema=PROTON_TWO_FACTOR_SCHEMA,
            errors=errors,
        )
