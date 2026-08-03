"""Tests for gpg-free Proton HTTP session."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock

import pytest

from proton_mikrotik_wg.proton_http import ProtonHttpSession
from proton_mikrotik_wg.proton_modulus import extract_srp_modulus


def _clearsigned_modulus(raw: bytes = b"x" * 256) -> str:
    body = base64.b64encode(raw).decode()
    return (
        "-----BEGIN PGP SIGNED MESSAGE-----\n"
        "Hash: SHA256\n"
        "\n"
        f"{body}\n"
        "-----BEGIN PGP SIGNATURE-----\n"
        "\n"
        "wnUEARYIABAFAlwB1j4JEDUFhcTpUY8mAAAB\n"
        "=TdF9\n"
        "-----END PGP SIGNATURE-----\n"
    )


class _FakeSrpUser:
    def __init__(self, password, modulus):
        self.password = password
        self.modulus = modulus
        self._ok = True

    def get_challenge(self):
        return b"client-ephemeral"

    def process_challenge(self, salt, server_challenge, version):
        return b"client-proof"

    def verify_session(self, server_proof):
        return None

    def authenticated(self):
        return self._ok


def _http_json(payload: dict, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.reason = "OK" if status == 200 else "ERR"
    resp.headers = {}
    resp.json.return_value = payload
    return resp


@pytest.fixture
def session():
    http = MagicMock()
    return ProtonHttpSession(
        api_url="https://vpn-api.proton.me",
        appversion="linux-vpn@4.3.0",
        user_agent="test-agent",
        http=http,
        srp_user_factory=_FakeSrpUser,
    )


def test_authenticate_stores_tokens_without_gpg(session):
    modulus = _clearsigned_modulus()
    assert extract_srp_modulus(modulus)  # sanity

    info = {
        "Code": 1000,
        "Modulus": modulus,
        "ServerEphemeral": base64.b64encode(b"server-ephemeral").decode(),
        "Salt": base64.b64encode(b"salt").decode(),
        "Version": 4,
        "SRPSession": "srp-1",
        "Username": "CanonicalUser",
    }
    auth = {
        "Code": 1000,
        "ServerProof": base64.b64encode(b"server-proof").decode(),
        "UID": "uid-1",
        "AccessToken": "access-1",
        "RefreshToken": "refresh-1",
        "Scope": "full self",
    }
    session._http.post.side_effect = [_http_json(info), _http_json(auth)]

    scope = session.authenticate("user@proton.me", "secret")
    assert scope == ["full", "self"]
    assert session.UID == "uid-1"
    assert session.AccessToken == "access-1"
    assert session.RefreshToken == "refresh-1"
    assert session._http.post.call_count == 2
    auth_payload = session._http.post.call_args_list[1].kwargs["json"]
    # Proton canonicalizes the account name in auth/info; /auth must use that.
    assert auth_payload["Username"] == "CanonicalUser"


def test_authenticate_maps_wrong_password(session):
    modulus = _clearsigned_modulus()
    info = {
        "Code": 1000,
        "Modulus": modulus,
        "ServerEphemeral": base64.b64encode(b"server-ephemeral").decode(),
        "Salt": base64.b64encode(b"salt").decode(),
        "Version": 4,
        "SRPSession": "srp-1",
    }
    auth = {"Code": 1000}  # missing ServerProof
    session._http.post.side_effect = [_http_json(info), _http_json(auth)]
    with pytest.raises(ValueError, match="Invalid password"):
        session.authenticate("user@proton.me", "bad")


def test_provide_2fa_updates_scope(session):
    session._session_data = {
        "UID": "uid-1",
        "AccessToken": "access-1",
        "RefreshToken": "refresh-1",
        "Scope": ["twofactor"],
    }
    session._http.post.return_value = _http_json(
        {"Code": 1000, "Scope": "full self"}
    )
    assert session.provide_2fa("123456") == ["full", "self"]
    assert session.Scope == ["full", "self"]


def test_refresh_updates_tokens(session):
    session._session_data = {
        "UID": "uid-1",
        "AccessToken": "access-old",
        "RefreshToken": "refresh-old",
        "Scope": ["full"],
    }
    session._http.post.return_value = _http_json(
        {
            "Code": 1000,
            "AccessToken": "access-new",
            "RefreshToken": "refresh-new",
        }
    )
    session.refresh()
    assert session.AccessToken == "access-new"
    assert session.RefreshToken == "refresh-new"


def test_from_dump_restores_tokens():
    dump = {
        "api_url": "https://vpn-api.proton.me",
        "appversion": "linux-vpn@4.3.0",
        "User-Agent": "test-agent",
        "session_data": {
            "UID": "uid-1",
            "AccessToken": "access-1",
            "RefreshToken": "refresh-1",
            "Scope": ["full"],
        },
    }
    restored = ProtonHttpSession.from_dump(dump, http=MagicMock())
    assert restored.UID == "uid-1"
    assert restored.AccessToken == "access-1"


def test_api_request_raises_on_proton_error_code(session):
    session._http.post.return_value = _http_json(
        {"Code": 8002, "Error": "Password is wrong"}
    )
    with pytest.raises(Exception) as exc:
        session.api_request("/auth", {"Username": "x"})
    assert type(exc.value).__name__ == "ProtonAPIError"
    assert "Password is wrong" in str(exc.value)


def test_api_request_parses_json_error_on_http_422(session):
    """Proton returns HTTP 422 with Code/Error JSON for auth failures."""
    session._http.post.return_value = _http_json(
        {"Code": 8002, "Error": "This email address does not exist."},
        status=422,
    )
    with pytest.raises(Exception) as exc:
        session.api_request("/auth", {"Username": "x"})
    assert type(exc.value).__name__ == "ProtonAPIError"
    assert "does not exist" in str(exc.value)


def test_api_request_maps_transport_errors(session):
    session._http.post.side_effect = ConnectionError("offline")
    with pytest.raises(Exception) as exc:
        session.api_request("/auth/info", {"Username": "x"})
    assert type(exc.value).__name__ == "ProtonTransportError"


def test_api_request_unknown_method(session):
    session._http = object()  # no HTTP verbs
    with pytest.raises(ValueError, match="Unknown method"):
        session.api_request("/auth", method="explode")


def test_api_request_http_error_status(session):
    resp = MagicMock()
    resp.status_code = 503
    resp.reason = "Service Unavailable"
    resp.json.side_effect = ValueError("no json")
    session._http.post.return_value = resp
    with pytest.raises(Exception) as exc:
        session.api_request("/auth", {"Username": "x"})
    assert "HTTP 503" in str(exc.value)


def test_api_request_invalid_json(session):
    resp = _http_json({})
    resp.json.side_effect = ValueError("nope")
    session._http.post.return_value = resp
    with pytest.raises(Exception) as exc:
        session.api_request("/auth", {"Username": "x"})
    assert "invalid JSON" in str(exc.value)


def test_api_request_rejects_non_dict_payload(session):
    resp = _http_json({})
    resp.json.return_value = ["not", "a", "dict"]
    session._http.post.return_value = resp
    with pytest.raises(Exception) as exc:
        session.api_request("/auth", {"Username": "x"})
    assert "unexpected" in str(exc.value)


def test_api_request_returns_dict_without_code(session):
    session._http.post.return_value = _http_json({"ok": True})
    # Force status 200 body without Proton Code field.
    session._http.post.return_value.json.return_value = {"ok": True}
    assert session.api_request("/custom", {"x": 1}) == {"ok": True}


def test_api_request_get_without_body(session):
    session._http.get.return_value = _http_json({"Code": 1000, "ok": True})
    assert session.api_request("/vpn/logicals")["ok"] is True


def test_authenticate_rejects_null_client_proof(session):
    class BadProof(_FakeSrpUser):
        def process_challenge(self, salt, server_challenge, version):
            return None

    session._srp_user_factory = BadProof
    modulus = _clearsigned_modulus()
    info = {
        "Code": 1000,
        "Modulus": modulus,
        "ServerEphemeral": base64.b64encode(b"server-ephemeral").decode(),
        "Salt": base64.b64encode(b"salt").decode(),
        "Version": 4,
        "SRPSession": "srp-1",
    }
    session._http.post.return_value = _http_json(info)
    with pytest.raises(ValueError, match="Invalid challenge"):
        session.authenticate("user@proton.me", "secret")


def test_authenticate_rejects_failed_server_proof(session):
    class BadAuth(_FakeSrpUser):
        def authenticated(self):
            return False

    session._srp_user_factory = BadAuth
    modulus = _clearsigned_modulus()
    info = {
        "Code": 1000,
        "Modulus": modulus,
        "ServerEphemeral": base64.b64encode(b"server-ephemeral").decode(),
        "Salt": base64.b64encode(b"salt").decode(),
        "Version": 4,
        "SRPSession": "srp-1",
    }
    auth = {
        "Code": 1000,
        "ServerProof": base64.b64encode(b"server-proof").decode(),
        "UID": "uid-1",
        "AccessToken": "access-1",
        "RefreshToken": "refresh-1",
        "Scope": "full",
    }
    session._http.post.side_effect = [_http_json(info), _http_json(auth)]
    with pytest.raises(ValueError, match="Invalid server proof"):
        session.authenticate("user@proton.me", "secret")


def test_provide_2fa_accepts_list_scope(session):
    session._session_data = {
        "UID": "uid-1",
        "AccessToken": "access-1",
        "RefreshToken": "refresh-1",
        "Scope": ["twofactor"],
    }
    session._http.post.return_value = _http_json(
        {"Code": 1000, "Scope": ["full", "self"]}
    )
    assert session.provide_2fa("123456") == ["full", "self"]


def test_logout_clears_tokens_and_ignores_revoke_errors(session):
    session._session_data = {
        "UID": "uid-1",
        "AccessToken": "access-1",
        "RefreshToken": "refresh-1",
        "Scope": ["full"],
    }
    session._http.headers["Authorization"] = "Bearer access-1"
    session._http.headers["x-pm-uid"] = "uid-1"
    session._http.delete.side_effect = ConnectionError("offline")
    session.logout()
    assert session._session_data == {}
    assert "Authorization" not in session._http.headers


def test_from_dump_without_tokens_skips_auth_headers():
    dump = {
        "api_url": "https://vpn-api.proton.me",
        "appversion": "linux-vpn@4.3.0",
        "User-Agent": "test-agent",
        "session_data": {},
    }
    restored = ProtonHttpSession.from_dump(dump, http=MagicMock())
    assert restored.UID is None
    assert "Authorization" not in restored._http.headers


def test_default_srp_user_factory_imports_proton_srp():
    from proton_mikrotik_wg.proton_http import _default_srp_user

    user = _default_srp_user("secret", b"\x00" * 256)
    assert hasattr(user, "get_challenge")


def test_session_uses_requests_session_by_default():
    session = ProtonHttpSession(
        api_url="https://vpn-api.proton.me",
        appversion="v",
        user_agent="ua",
        srp_user_factory=_FakeSrpUser,
    )
    assert session._http is not None


def test_api_request_reraises_value_error_from_transport(session):
    session._http.post.side_effect = ValueError("bad method wiring")
    with pytest.raises(ValueError, match="bad method wiring"):
        session.api_request("/auth", {"Username": "x"})
