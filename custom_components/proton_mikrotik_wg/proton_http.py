"""Proton VPN HTTP session that does not require a system gpg binary."""

from __future__ import annotations

import base64
from typing import Any, Callable

import requests

from .proton_modulus import extract_srp_modulus

SrpUserFactory = Callable[[str, bytes], Any]


class ProtonAPIError(Exception):
    """Proton returned a non-success API code."""

    def __init__(self, code: int, error: str) -> None:
        self.code = code
        self.error = error
        super().__init__(error)


class ProtonTransportError(Exception):
    """HTTP transport failure talking to Proton."""


def _default_srp_user(password: str, modulus: bytes) -> Any:
    from proton.srp import User

    return User(password, modulus)


class ProtonHttpSession:
    """Minimal Proton account session: login, 2FA, refresh, token properties."""

    def __init__(
        self,
        *,
        api_url: str,
        appversion: str,
        user_agent: str,
        http: requests.Session | None = None,
        srp_user_factory: SrpUserFactory = _default_srp_user,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._appversion = appversion
        self._user_agent = user_agent
        self._http = http or requests.Session()
        self._srp_user_factory = srp_user_factory
        self._session_data: dict[str, Any] = {}
        self._http.headers.update(
            {
                "x-pm-apiversion": "3",
                "Accept": "application/vnd.protonmail.v1+json",
                "x-pm-appversion": appversion,
                "User-Agent": user_agent,
            }
        )

    @classmethod
    def from_dump(
        cls,
        dump: dict[str, Any],
        *,
        http: requests.Session | None = None,
        srp_user_factory: SrpUserFactory = _default_srp_user,
    ) -> ProtonHttpSession:
        """Restore a session from stored tokens (config entry dump shape)."""
        session = cls(
            api_url=dump["api_url"],
            appversion=dump["appversion"],
            user_agent=dump["User-Agent"],
            http=http,
            srp_user_factory=srp_user_factory,
        )
        session._session_data = dict(dump.get("session_data") or {})
        if session.UID is not None and session.AccessToken is not None:
            session._http.headers["x-pm-uid"] = session.UID
            session._http.headers["Authorization"] = f"Bearer {session.AccessToken}"
        return session

    def api_request(
        self,
        endpoint: str,
        jsondata: dict[str, Any] | None = None,
        *,
        method: str | None = None,
    ) -> dict[str, Any]:
        """Call a Proton API endpoint and return the JSON body."""
        verb = (method or ("get" if jsondata is None else "post")).lower()
        fct = getattr(self._http, verb, None)
        if fct is None:
            raise ValueError(f"Unknown method: {verb}")
        try:
            response = fct(f"{self._api_url}{endpoint}", json=jsondata, timeout=30)
        except Exception as err:  # noqa: BLE001 — network stack varies by env
            if isinstance(err, (ProtonAPIError, ProtonTransportError, ValueError)):
                raise
            raise ProtonTransportError(str(err)) from err

        if response.status_code >= 400:
            raise ProtonTransportError(
                f"HTTP {response.status_code}: {response.reason}"
            )

        try:
            payload = response.json()
        except ValueError as err:
            raise ProtonTransportError("invalid JSON from Proton") from err

        if not isinstance(payload, dict):
            raise ProtonTransportError("unexpected Proton response shape")
        code = payload.get("Code", 0)
        if code != 1000:
            raise ProtonAPIError(int(code), str(payload.get("Error", "Proton error")))
        return payload

    def authenticate(self, username: str, password: str) -> list[str]:
        """SRP login against Proton; returns the session scope list."""
        self.logout()
        info = self.api_request("/auth/info", {"Username": username})
        modulus = extract_srp_modulus(info["Modulus"])
        server_challenge = base64.b64decode(info["ServerEphemeral"])
        salt = base64.b64decode(info["Salt"])
        version = info["Version"]

        usr = self._srp_user_factory(password, modulus)
        client_challenge = usr.get_challenge()
        client_proof = usr.process_challenge(salt, server_challenge, version)
        if client_proof is None:
            raise ValueError("Invalid challenge")

        auth = self.api_request(
            "/auth",
            {
                "Username": username,
                "ClientEphemeral": base64.b64encode(client_challenge).decode("utf8"),
                "ClientProof": base64.b64encode(client_proof).decode("utf8"),
                "SRPSession": info["SRPSession"],
            },
        )
        if "ServerProof" not in auth:
            raise ValueError("Invalid password")
        usr.verify_session(base64.b64decode(auth["ServerProof"]))
        if not usr.authenticated():
            raise ValueError("Invalid server proof")

        scope = auth["Scope"].split()
        self._session_data = {
            "UID": auth["UID"],
            "AccessToken": auth["AccessToken"],
            "RefreshToken": auth["RefreshToken"],
            "Scope": scope,
        }
        self._http.headers["x-pm-uid"] = self.UID
        self._http.headers["Authorization"] = f"Bearer {self.AccessToken}"
        return scope

    def provide_2fa(self, code: str) -> list[str]:
        """Submit TOTP and return the upgraded scope list."""
        ret = self.api_request("/auth/2fa", {"TwoFactorCode": code})
        scope = ret["Scope"]
        if isinstance(scope, str):
            scope = scope.split()
        self._session_data["Scope"] = list(scope)
        return list(self.Scope)

    def logout(self) -> None:
        """Clear local tokens; best-effort revoke when a session exists."""
        if self._session_data:
            try:
                self.api_request("/auth", method="delete")
            except (ProtonAPIError, ProtonTransportError):
                pass
            self._http.headers.pop("Authorization", None)
            self._http.headers.pop("x-pm-uid", None)
            self._session_data = {}

    def refresh(self) -> None:
        """Refresh access/refresh tokens in place."""
        refresh_response = self.api_request(
            "/auth/refresh",
            {
                "ResponseType": "token",
                "GrantType": "refresh_token",
                "RefreshToken": self.RefreshToken,
                "RedirectURI": "http://protonmail.ch",
            },
        )
        self._session_data["AccessToken"] = refresh_response["AccessToken"]
        self._session_data["RefreshToken"] = refresh_response["RefreshToken"]
        self._http.headers["Authorization"] = f"Bearer {self.AccessToken}"

    @property
    def UID(self) -> str | None:
        return self._session_data.get("UID")

    @property
    def AccessToken(self) -> str | None:
        return self._session_data.get("AccessToken")

    @property
    def RefreshToken(self) -> str | None:
        return self._session_data.get("RefreshToken")

    @property
    def Scope(self) -> list[str]:
        return list(self._session_data.get("Scope") or [])
