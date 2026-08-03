"""Tests for MikroTik RouterOS connectivity helper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from proton_mikrotik_wg import mikrotik_client
from proton_mikrotik_wg.mikrotik_client import (
    CannotConnectMikroTik,
    InvalidMikroTikAuth,
    check_mikrotik_connection,
    open_mikrotik_api,
)


def test_check_mikrotik_connection_succeeds_with_resource_print():
    api = MagicMock()
    api.path.return_value = iter([{"version": "7.0"}])
    connect = MagicMock(return_value=api)

    check_mikrotik_connection(
        host="mikrotik.lan",
        username="admin",
        password="secret",
        port=8729,
        use_ssl=True,
        connect_fn=connect,
    )

    connect.assert_called_once()
    kwargs = connect.call_args.kwargs
    assert kwargs["host"] == "mikrotik.lan"
    assert kwargs["username"] == "admin"
    assert kwargs["password"] == "secret"
    assert kwargs["port"] == 8729
    assert callable(kwargs["ssl_wrapper"])
    api.path.assert_called_with("system", "resource")
    api.close.assert_called_once()


def test_check_mikrotik_connection_without_ssl_omits_wrapper():
    api = MagicMock()
    api.path.return_value = iter([{"version": "7.0"}])
    connect = MagicMock(return_value=api)

    check_mikrotik_connection(
        host="mikrotik.lan",
        username="admin",
        password="secret",
        port=8728,
        use_ssl=False,
        connect_fn=connect,
    )

    assert "ssl_wrapper" not in connect.call_args.kwargs


def test_check_mikrotik_connection_maps_auth_errors():
    connect = MagicMock(side_effect=Exception("invalid user name or password"))
    with pytest.raises(InvalidMikroTikAuth):
        check_mikrotik_connection(
            host="mikrotik.lan",
            username="admin",
            password="bad",
            connect_fn=connect,
        )


def test_check_mikrotik_connection_maps_other_errors():
    connect = MagicMock(side_effect=OSError("timed out"))
    with pytest.raises(CannotConnectMikroTik):
        check_mikrotik_connection(
            host="mikrotik.lan",
            username="admin",
            password="secret",
            connect_fn=connect,
        )


def test_check_mikrotik_connection_maps_resource_errors():
    api = MagicMock()
    api.path.side_effect = RuntimeError("broken")
    connect = MagicMock(return_value=api)
    with pytest.raises(CannotConnectMikroTik, match="broken"):
        check_mikrotik_connection(
            host="mikrotik.lan",
            username="admin",
            password="secret",
            connect_fn=connect,
        )
    api.close.assert_called_once()


def test_check_mikrotik_connection_skips_close_when_missing():
    api = MagicMock(spec=["path"])
    api.path.return_value = iter([{"version": "7.0"}])
    connect = MagicMock(return_value=api)
    check_mikrotik_connection(
        host="mikrotik.lan",
        username="admin",
        password="secret",
        connect_fn=connect,
    )


def test_open_mikrotik_api_returns_session():
    api = MagicMock()
    connect = MagicMock(return_value=api)
    result = open_mikrotik_api(
        host="mikrotik.lan",
        username="admin",
        password="secret",
        connect_fn=connect,
    )
    assert result is api


def test_open_mikrotik_api_maps_auth_and_connect_errors():
    with pytest.raises(InvalidMikroTikAuth):
        open_mikrotik_api(
            host="h",
            username="u",
            password="p",
            connect_fn=MagicMock(side_effect=Exception("bad username")),
        )
    with pytest.raises(CannotConnectMikroTik):
        open_mikrotik_api(
            host="h",
            username="u",
            password="p",
            use_ssl=False,
            connect_fn=MagicMock(side_effect=OSError("down")),
        )


def test_default_ssl_wrapper_disables_hostname_checks():
    sock = MagicMock()
    context = MagicMock()
    with patch(
        "proton_mikrotik_wg.mikrotik_client.ssl.create_default_context",
        return_value=context,
    ):
        mikrotik_client._default_ssl_wrapper(sock)
    assert context.check_hostname is False
    assert context.verify_mode == mikrotik_client.ssl.CERT_NONE
    context.wrap_socket.assert_called_once_with(sock)


def test_default_connect_uses_librouteros():
    fake_connect = MagicMock(return_value="api")
    fake_module = MagicMock(connect=fake_connect)
    with patch.dict("sys.modules", {"librouteros": fake_module}):
        result = mikrotik_client._default_connect(host="h", username="u", password="p")
    assert result == "api"
    fake_connect.assert_called_once_with(host="h", username="u", password="p")
