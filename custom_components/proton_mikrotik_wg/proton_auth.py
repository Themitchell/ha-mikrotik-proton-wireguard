"""Proton account login helpers (SRP via proton-client, injectable for tests)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, NoReturn, Protocol


class InvalidCredentials(Exception):
    """Username/password or 2FA code was rejected."""


class CannotConnect(Exception):
    """Network or transport failure talking to Proton."""


class TwoFactorRequired(Exception):
    """Password accepted but TOTP is still required."""

    def __init__(self, session: ProtonSession, data: ProtonSessionData) -> None:
        super().__init__("two-factor authentication required")
        self.session = session
        self.data = data


# Exception class names from proton.exceptions / our HTTP client.
_AUTH_ERROR_NAMES = frozenset({"ProtonError", "ProtonAPIError"})
_CONNECT_ERROR_NAMES = frozenset(
    {
        "ProtonNetworkError",
        "ProtonTransportError",
        "NewConnectionError",
        "ConnectionTimeOutError",
        "TLSPinningError",
        "UnknownConnectionError",
        "OSError",
    }
)


def _reraise_mapped_proton_error(err: Exception) -> NoReturn:
    """Map proton-client errors to InvalidCredentials or CannotConnect."""
    name = type(err).__name__
    if name in _AUTH_ERROR_NAMES:
        raise InvalidCredentials(str(err)) from err
    if name in _CONNECT_ERROR_NAMES:
        raise CannotConnect(str(err)) from err
    raise err


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

    def refresh(self) -> None:
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

    @property
    def Scope(self) -> list[str]:
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
    try:
        session = create_session()
        scope = list(session.authenticate(username, password))
    except ValueError as err:
        raise InvalidCredentials("invalid username or password") from err
    except Exception as err:  # noqa: BLE001 — map proton client errors
        _reraise_mapped_proton_error(err)

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


def refresh_session(session: ProtonSession, *, username: str) -> ProtonSessionData:
    """Refresh access/refresh tokens on an authenticated Proton session."""
    try:
        session.refresh()
    except Exception as err:  # noqa: BLE001
        raise InvalidCredentials("session refresh failed") from err
    scope = list(session.Scope or [])
    return _session_data(username, session, scope)


DEFAULT_API_URL = "https://api.protonvpn.ch"
# Prefer legacy VPN API first — some hosts block or challenge vpn-api.proton.me.
DEFAULT_API_URLS = (
    "https://api.protonvpn.ch",
    "https://vpn-api.proton.me",
)
DEFAULT_APP_VERSION = "linux-vpn@4.3.0"
DEFAULT_USER_AGENT = "ProtonVPN/4.3.0 (Linux; HomeAssistant)"


def session_factory_for_url(api_url: str) -> SessionFactory:
    """Build a session factory pinned to one Proton API base URL."""

    def factory() -> Any:
        from .proton_http import ProtonHttpSession

        return ProtonHttpSession(
            api_url=api_url,
            appversion=DEFAULT_APP_VERSION,
            user_agent=DEFAULT_USER_AGENT,
        )

    return factory


def login_with_password_failover(
    username: str,
    password: str,
) -> ProtonSessionData:
    """Login trying each known Proton API host until one connects."""
    last_connect_error: CannotConnect | None = None
    for api_url in DEFAULT_API_URLS:
        try:
            return login_with_password(
                username,
                password,
                create_session=session_factory_for_url(api_url),
            )
        except CannotConnect as err:
            last_connect_error = err
    assert last_connect_error is not None
    raise last_connect_error


def session_dump_from_data(data: ProtonSessionData) -> dict[str, Any]:
    """Build a proton.api.Session.load()-compatible dump from stored tokens."""
    return {
        "api_url": DEFAULT_API_URL,
        "appversion": DEFAULT_APP_VERSION,
        "User-Agent": DEFAULT_USER_AGENT,
        "cookies": {},
        "session_data": {
            "UID": data.uid,
            "AccessToken": data.access_token,
            "RefreshToken": data.refresh_token,
            "Scope": list(data.scope),
        },
    }


SessionLoader = Callable[[dict[str, Any]], ProtonSession]


def default_session_loader(dump: dict[str, Any]) -> Any:
    """Restore a Proton HTTP session from a dump dict (no system gpg)."""
    from .proton_http import ProtonHttpSession

    return ProtonHttpSession.from_dump(dump)


class ProtonAuthClient:
    """Holds Proton session tokens and refreshes them for API use."""

    def __init__(
        self,
        data: ProtonSessionData,
        *,
        load_session: SessionLoader = default_session_loader,
    ) -> None:
        self._data = data
        self._load_session = load_session
        self._live: ProtonSession | None = None

    @property
    def data(self) -> ProtonSessionData:
        """Current persisted token set."""
        return self._data

    def live_session(self) -> ProtonSession:
        """Return a hydrated Proton client for the current tokens."""
        if self._live is None:
            self._live = self._load_session(session_dump_from_data(self._data))
        return self._live

    def refresh(self) -> ProtonSessionData:
        """Refresh tokens, update stored data, and return the new set."""
        updated = refresh_session(self.live_session(), username=self._data.username)
        self._data = updated
        return updated


def default_session_factory() -> Any:
    """Create a Proton HTTP session that does not require system gpg."""
    return session_factory_for_url(DEFAULT_API_URL)()

