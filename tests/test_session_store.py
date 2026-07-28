from proton_mikrotik_wg.const import (
    CONF_ACCESS_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_SCOPE,
    CONF_UID,
    CONF_USERNAME,
)
from proton_mikrotik_wg.proton_auth import ProtonSessionData
from proton_mikrotik_wg.session_store import (
    entry_data_from_session,
    session_data_from_entry,
)


def test_session_data_from_entry_round_trip():
    entry = {
        CONF_USERNAME: "user@proton.me",
        CONF_UID: "uid-1",
        CONF_ACCESS_TOKEN: "access-1",
        CONF_REFRESH_TOKEN: "refresh-1",
        CONF_SCOPE: ["full", "self"],
    }
    data = session_data_from_entry(entry)
    assert data.username == "user@proton.me"
    assert data.uid == "uid-1"
    assert data.access_token == "access-1"
    assert data.refresh_token == "refresh-1"
    assert data.scope == ("full", "self")


def test_session_data_from_entry_defaults_missing_scope():
    entry = {
        CONF_USERNAME: "user@proton.me",
        CONF_UID: "uid-1",
        CONF_ACCESS_TOKEN: "access-1",
        CONF_REFRESH_TOKEN: "refresh-1",
    }
    data = session_data_from_entry(entry)
    assert data.scope == ()


def test_entry_data_from_session_round_trip():
    session = ProtonSessionData(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-2",
        refresh_token="refresh-2",
        scope=("full",),
    )
    entry = entry_data_from_session(session)
    assert entry[CONF_ACCESS_TOKEN] == "access-2"
    assert entry[CONF_REFRESH_TOKEN] == "refresh-2"
    assert entry[CONF_SCOPE] == ["full"]
    assert session_data_from_entry(entry) == session
