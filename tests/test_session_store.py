from proton_mikrotik_wg.const import (
    CONF_ACCESS_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_SCOPE,
    CONF_UID,
    CONF_USERNAME,
)
from proton_mikrotik_wg.session_store import session_data_from_entry


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
