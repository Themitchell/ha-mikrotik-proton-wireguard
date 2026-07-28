from unittest.mock import MagicMock

import pytest

from proton_mikrotik_wg.proton_auth import (
    DEFAULT_API_URL,
    InvalidCredentials,
    ProtonAuthClient,
    ProtonSessionData,
    refresh_session,
    session_dump_from_data,
)


def _data(**overrides) -> ProtonSessionData:
    base = dict(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-old",
        refresh_token="refresh-old",
        scope=("full", "self"),
    )
    base.update(overrides)
    return ProtonSessionData(**base)


def test_refresh_session_returns_updated_tokens():
    session = MagicMock()
    session.UID = "uid-1"
    session.AccessToken = "access-old"
    session.RefreshToken = "refresh-old"
    session.Scope = ["full", "self"]

    def do_refresh():
        session.AccessToken = "access-new"
        session.RefreshToken = "refresh-new"
        session.Scope = ["full", "self"]

    session.refresh.side_effect = do_refresh

    updated = refresh_session(session, username="user@proton.me")
    assert updated == ProtonSessionData(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-new",
        refresh_token="refresh-new",
        scope=("full", "self"),
    )
    session.refresh.assert_called_once_with()


def test_refresh_session_maps_failures_to_invalid_credentials():
    session = MagicMock()
    session.refresh.side_effect = RuntimeError("expired")
    with pytest.raises(InvalidCredentials):
        refresh_session(session, username="user@proton.me")


def test_refresh_session_rejects_incomplete_tokens_after_refresh():
    session = MagicMock()
    session.UID = "uid-1"
    session.AccessToken = "access-old"
    session.RefreshToken = "refresh-old"
    session.Scope = ["full"]

    def do_refresh():
        session.AccessToken = None
        session.RefreshToken = "refresh-new"

    session.refresh.side_effect = do_refresh
    with pytest.raises(InvalidCredentials):
        refresh_session(session, username="user@proton.me")


def test_session_dump_from_data_includes_tokens():
    dump = session_dump_from_data(_data())
    assert dump["api_url"] == DEFAULT_API_URL
    assert dump["session_data"]["UID"] == "uid-1"
    assert dump["session_data"]["AccessToken"] == "access-old"
    assert dump["session_data"]["RefreshToken"] == "refresh-old"
    assert dump["session_data"]["Scope"] == ["full", "self"]


def test_auth_client_live_session_uses_loader_once():
    live = MagicMock(name="live")
    loader = MagicMock(return_value=live)
    client = ProtonAuthClient(_data(), load_session=loader)

    assert client.live_session() is live
    assert client.live_session() is live
    loader.assert_called_once()
    dump = loader.call_args.args[0]
    assert dump["session_data"]["AccessToken"] == "access-old"


def test_auth_client_refresh_updates_stored_data():
    live = MagicMock()
    live.UID = "uid-1"
    live.AccessToken = "access-old"
    live.RefreshToken = "refresh-old"
    live.Scope = ["full", "self"]

    def do_refresh():
        live.AccessToken = "access-new"
        live.RefreshToken = "refresh-new"

    live.refresh.side_effect = do_refresh
    client = ProtonAuthClient(_data(), load_session=lambda dump: live)

    updated = client.refresh()
    assert updated.access_token == "access-new"
    assert updated.refresh_token == "refresh-new"
    assert client.data.access_token == "access-new"


def test_auth_client_refresh_propagates_invalid_credentials():
    live = MagicMock()
    live.refresh.side_effect = RuntimeError("nope")
    client = ProtonAuthClient(_data(), load_session=lambda dump: live)
    with pytest.raises(InvalidCredentials):
        client.refresh()


def test_default_session_loader_uses_proton_session_load():
    import sys
    from types import ModuleType

    loaded = MagicMock(name="loaded-session")
    fake_session_cls = MagicMock()
    fake_session_cls.load.return_value = loaded
    proton_mod = ModuleType("proton")
    proton_api = ModuleType("proton.api")
    proton_api.Session = fake_session_cls
    sys.modules["proton"] = proton_mod
    sys.modules["proton.api"] = proton_api

    from proton_mikrotik_wg.proton_auth import default_session_loader

    dump = session_dump_from_data(_data())
    assert default_session_loader(dump) is loaded
    fake_session_cls.load.assert_called_once_with(dump, TLSPinning=True)


def test_refresh_session_handles_none_scope():
    session = MagicMock()
    session.UID = "uid-1"
    session.AccessToken = "a"
    session.RefreshToken = "r"
    session.Scope = None

    def do_refresh():
        session.AccessToken = "a2"
        session.RefreshToken = "r2"
        session.Scope = None

    session.refresh.side_effect = do_refresh
    updated = refresh_session(session, username="user@proton.me")
    assert updated.scope == ()
