from unittest.mock import MagicMock

import pytest

from proton_mikrotik_wg.proton_auth import (
    CannotConnect,
    InvalidCredentials,
    TwoFactorRequired,
    login_with_password,
    scopes_need_2fa,
    submit_two_factor,
)


def test_scopes_need_2fa_when_twofactor_present():
    assert scopes_need_2fa(["twofactor", "self"]) is True
    assert scopes_need_2fa(["full", "self"]) is False


def _mock_session(*, scope_after_auth, scope_after_2fa=None):
    session = MagicMock()
    session.authenticate.return_value = scope_after_auth
    session.UID = "uid-1"
    session.AccessToken = "access-1"
    session.RefreshToken = "refresh-1"
    if scope_after_2fa is not None:
        session.provide_2fa.return_value = scope_after_2fa
    return session


def test_login_with_password_returns_session_when_no_2fa():
    session = _mock_session(scope_after_auth=["full", "self"])
    data = login_with_password(
        "user@proton.me",
        "secret",
        create_session=lambda: session,
    )
    assert data.uid == "uid-1"
    assert data.access_token == "access-1"
    assert data.refresh_token == "refresh-1"
    assert data.username == "user@proton.me"
    session.authenticate.assert_called_once_with("user@proton.me", "secret")


def test_login_with_password_raises_two_factor_required():
    session = _mock_session(scope_after_auth=["twofactor", "self"])
    with pytest.raises(TwoFactorRequired) as exc:
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )
    assert exc.value.data.uid == "uid-1"
    assert exc.value.session is session


def test_login_with_password_maps_invalid_password():
    session = MagicMock()
    session.authenticate.side_effect = ValueError("Invalid password")
    with pytest.raises(InvalidCredentials):
        login_with_password(
            "user@proton.me",
            "wrong",
            create_session=lambda: session,
        )


def test_submit_two_factor_returns_upgraded_session():
    session = _mock_session(
        scope_after_auth=["twofactor"],
        scope_after_2fa=["full", "self"],
    )
    data = submit_two_factor(session, "123456", username="user@proton.me")
    assert "full" in data.scope
    assert "twofactor" not in data.scope
    session.provide_2fa.assert_called_once_with("123456")


def test_login_rejects_incomplete_session_tokens():
    session = MagicMock()
    session.authenticate.return_value = ["full"]
    session.UID = None
    session.AccessToken = "access"
    session.RefreshToken = "refresh"
    with pytest.raises(InvalidCredentials):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )


def test_login_maps_proton_error():
    session = MagicMock()

    class ProtonError(Exception):
        pass

    session.authenticate.side_effect = ProtonError("nope")
    with pytest.raises(InvalidCredentials):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )


def test_login_rethrows_unexpected_errors():
    session = MagicMock()
    session.authenticate.side_effect = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )


def test_submit_two_factor_maps_provider_errors():
    session = _mock_session(
        scope_after_auth=["twofactor"],
        scope_after_2fa=["full"],
    )
    session.provide_2fa.side_effect = RuntimeError("bad code")
    with pytest.raises(InvalidCredentials):
        submit_two_factor(session, "000000", username="user@proton.me")


def test_submit_two_factor_rejects_lingering_twofactor_scope():
    session = _mock_session(
        scope_after_auth=["twofactor"],
        scope_after_2fa=["twofactor", "self"],
    )
    with pytest.raises(InvalidCredentials):
        submit_two_factor(session, "123456", username="user@proton.me")


def test_login_rejects_incomplete_access_token():
    session = MagicMock()
    session.authenticate.return_value = ["full"]
    session.UID = "uid"
    session.AccessToken = None
    session.RefreshToken = "refresh"
    with pytest.raises(InvalidCredentials):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )


def test_login_rejects_incomplete_refresh_token():
    session = MagicMock()
    session.authenticate.return_value = ["full"]
    session.UID = "uid"
    session.AccessToken = "access"
    session.RefreshToken = None
    with pytest.raises(InvalidCredentials):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )


def test_login_maps_network_error_names():
    session = MagicMock()

    class NewConnectionError(Exception):
        pass

    session.authenticate.side_effect = NewConnectionError("offline")
    with pytest.raises(CannotConnect):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )


def test_scopes_need_2fa_empty_scope():
    assert scopes_need_2fa([]) is False
    assert scopes_need_2fa(()) is False


def test_login_maps_proton_network_error_name():
    session = MagicMock()

    class ProtonNetworkError(Exception):
        pass

    session.authenticate.side_effect = ProtonNetworkError("timeout")
    with pytest.raises(CannotConnect):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )


def test_login_maps_unknown_connection_error():
    session = MagicMock()

    class UnknownConnectionError(Exception):
        pass

    session.authenticate.side_effect = UnknownConnectionError(
        "Timeout cannot be a boolean value"
    )
    with pytest.raises(CannotConnect, match="Timeout cannot be a boolean"):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )


def test_login_maps_tls_pinning_and_timeout_errors():
    session = MagicMock()

    class TLSPinningError(Exception):
        pass

    class ConnectionTimeOutError(Exception):
        pass

    session.authenticate.side_effect = TLSPinningError("pin mismatch")
    with pytest.raises(CannotConnect):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )

    session.authenticate.side_effect = ConnectionTimeOutError("timed out")
    with pytest.raises(CannotConnect):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )


def test_default_session_factory_builds_proton_session():
    from unittest.mock import patch

    fake = MagicMock(name="ProtonHttpSession")
    with patch(
        "proton_mikrotik_wg.proton_http.ProtonHttpSession", fake
    ):
        from proton_mikrotik_wg.proton_auth import default_session_factory

        default_session_factory()
    fake.assert_called_once()
    kwargs = fake.call_args.kwargs
    assert kwargs["api_url"] == "https://vpn-api.proton.me"
    assert "TLSPinning" not in kwargs


def test_default_session_loader_disables_tls_pinning():
    from unittest.mock import patch

    fake = MagicMock(name="ProtonHttpSession")
    dump = {"api_url": "https://vpn-api.proton.me"}
    with patch(
        "proton_mikrotik_wg.proton_http.ProtonHttpSession"
    ) as cls:
        from proton_mikrotik_wg.proton_auth import default_session_loader

        default_session_loader(dump)
    cls.from_dump.assert_called_once_with(dump)


def test_login_maps_oserror_from_session_create():
    def boom():
        raise OSError("Unable to run gpg (gpg) - it may not be available.")

    with pytest.raises(CannotConnect, match="gpg"):
        login_with_password("user@proton.me", "secret", create_session=boom)


def test_login_maps_proton_transport_error():
    session = MagicMock()

    class ProtonTransportError(Exception):
        pass

    session.authenticate.side_effect = ProtonTransportError("offline")
    with pytest.raises(CannotConnect):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )


def test_login_maps_proton_api_error():
    session = MagicMock()

    class ProtonAPIError(Exception):
        pass

    session.authenticate.side_effect = ProtonAPIError("Password is wrong")
    with pytest.raises(InvalidCredentials):
        login_with_password(
            "user@proton.me",
            "secret",
            create_session=lambda: session,
        )
