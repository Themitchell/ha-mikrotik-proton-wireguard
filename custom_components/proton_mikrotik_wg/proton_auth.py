"""Proton account login helpers (SRP via proton-client, injectable for tests)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol


class InvalidCredentials(Exception):
    """Username/password or 2FA code was rejected."""


class TwoFactorRequired(Exception):
    """Password accepted but TOTP is still required."""

    def __init__(self, session: ProtonSession, data: ProtonSessionData) -> None:
        super().__init__("two-factor authentication required")
        self.session = session
        self.data = data


@dataclass(frozen=True)
class ProtonSessionData:
    """Persisted API session after a successful login (and 2FA if needed)."""

    username: str
    uid: str
    access_token: str
    refresh_token: str
    scope: tuple[str, ...]


class ProtonSession(Protocol):
    """Minimal surface of proton.api.Session used by this integration."""

    def authenticate(self, username: str, password: str) -> list[str]:
        ...

    def provide_2fa(self, code: str) -> list[str]:
        ...

    @property
    def UID(self) -> str | None:
        ...

    @property
    def AccessToken(self) -> str | None:
        ...

    @property
    def RefreshToken(self) -> str | None:
        ...


SessionFactory = Callable[[], ProtonSession]


def scopes_need_2fa(scope: list[str] | tuple[str, ...]) -> bool:
    """Return True when Proton still requires a TOTP challenge."""
    return "twofactor" in scope


def _session_data(username: str, session: ProtonSession, scope: list[str]) -> ProtonSessionData:
    uid = session.UID
    access = session.AccessToken
    refresh = session.RefreshToken
    if not uid or not access or not refresh:
        raise InvalidCredentials("incomplete session from Proton")
    return ProtonSessionData(
        username=username,
        uid=uid,
        access_token=access,
        refresh_token=refresh,
        scope=tuple(scope),
    )


def login_with_password(
    username: str,
    password: str,
    *,
    create_session: SessionFactory,
) -> ProtonSessionData:
    """Authenticate with username/password. Raises TwoFactorRequired if TOTP needed."""
    session = create_session()
    try:
        scope = list(session.authenticate(username, password))
    except ValueError as err:
        raise InvalidCredentials("invalid username or password") from err
    except Exception as err:  # noqa: BLE001 — map proton client errors
        # proton.exceptions.ProtonError and network failures
        name = type(err).__name__
        if name in {"ProtonError", "ProtonNetworkError", "NewConnectionError"}:
            raise InvalidCredentials(str(err)) from err
        raise

    data = _session_data(username, session, scope)
    if scopes_need_2fa(scope):
        raise TwoFactorRequired(session, data)
    return data


def submit_two_factor(
    session: ProtonSession,
    code: str,
    *,
    username: str,
) -> ProtonSessionData:
    """Complete TOTP and return an upgraded session."""
    try:
        scope = list(session.provide_2fa(code))
    except Exception as err:  # noqa: BLE001
        raise InvalidCredentials("invalid two-factor code") from err
    if scopes_need_2fa(scope):
        raise InvalidCredentials("two-factor authentication incomplete")
    return _session_data(username, session, scope)


def default_session_factory() -> Any:
    """Create a real proton.api.Session for production use."""
    from proton.api import Session

    return Session(
        api_url="https://vpn-api.proton.me",
        appversion="linux-vpn@4.3.0",
        user_agent="ProtonVPN/4.3.0 (Linux; HomeAssistant)",
    )
