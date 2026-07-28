import pytest
import voluptuous as vol

from proton_mikrotik_wg.schemas import (
    PROTON_CREDENTIALS_SCHEMA,
    PROTON_TWO_FACTOR_SCHEMA,
)


def test_proton_credentials_schema_requires_username_and_password():
    data = PROTON_CREDENTIALS_SCHEMA(
        {"username": "user@proton.me", "password": "secret"}
    )
    assert data["username"] == "user@proton.me"
    assert data["password"] == "secret"


def test_proton_credentials_schema_rejects_missing_password():
    with pytest.raises(vol.Invalid):
        PROTON_CREDENTIALS_SCHEMA({"username": "user@proton.me"})


def test_proton_two_factor_schema_requires_totp():
    assert PROTON_TWO_FACTOR_SCHEMA({"totp": "123456"})["totp"] == "123456"
    with pytest.raises(vol.Invalid):
        PROTON_TWO_FACTOR_SCHEMA({})
