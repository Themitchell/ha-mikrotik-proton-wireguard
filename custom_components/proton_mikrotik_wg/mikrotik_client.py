"""MikroTik RouterOS API connection helpers."""

from __future__ import annotations

import ssl
from typing import Any, Callable


class CannotConnectMikroTik(Exception):
    """Raised when the MikroTik API cannot be reached."""


class InvalidMikroTikAuth(Exception):
    """Raised when MikroTik rejects the username/password."""


def _default_ssl_wrapper(sock: Any) -> Any:
    """Wrap a socket for api-ssl (accept self-signed home LAN certs)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock)


def _default_connect(**kwargs: Any) -> Any:
    from librouteros import connect

    return connect(**kwargs)


def check_mikrotik_connection(
    *,
    host: str,
    username: str,
    password: str,
    port: int = 8729,
    use_ssl: bool = True,
    connect_fn: Callable[..., Any] | None = None,
) -> None:
    """Verify RouterOS API login by reading /system/resource."""
    connect = connect_fn or _default_connect
    kwargs: dict[str, Any] = {
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if use_ssl:
        kwargs["ssl_wrapper"] = _default_ssl_wrapper

    try:
        api = connect(**kwargs)
    except Exception as err:  # noqa: BLE001
        message = str(err).lower()
        if "password" in message or "user name" in message or "username" in message:
            raise InvalidMikroTikAuth(str(err)) from err
        raise CannotConnectMikroTik(str(err)) from err

    try:
        list(api.path("system", "resource"))
    except Exception as err:  # noqa: BLE001
        raise CannotConnectMikroTik(str(err)) from err
    finally:
        close = getattr(api, "close", None)
        if callable(close):
            close()


def open_mikrotik_api(
    *,
    host: str,
    username: str,
    password: str,
    port: int = 8729,
    use_ssl: bool = True,
    connect_fn: Callable[..., Any] | None = None,
) -> Any:
    """Open a RouterOS API session (caller must close)."""
    connect = connect_fn or _default_connect
    kwargs: dict[str, Any] = {
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if use_ssl:
        kwargs["ssl_wrapper"] = _default_ssl_wrapper
    try:
        return connect(**kwargs)
    except Exception as err:  # noqa: BLE001
        message = str(err).lower()
        if "password" in message or "user name" in message or "username" in message:
            raise InvalidMikroTikAuth(str(err)) from err
        raise CannotConnectMikroTik(str(err)) from err
