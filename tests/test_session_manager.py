"""Tests for ProtonSessionManager."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ha_stubs import ConfigEntryAuthFailed
from proton_mikrotik_wg.const import CONF_ACCESS_TOKEN, CONF_REFRESH_TOKEN
from proton_mikrotik_wg.proton_auth import InvalidCredentials, ProtonSessionData
from proton_mikrotik_wg.session_manager import ProtonSessionManager


def _session(**overrides) -> ProtonSessionData:
    base = dict(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-old",
        refresh_token="refresh-old",
        scope=("full", "self"),
    )
    base.update(overrides)
    return ProtonSessionData(**base)


@pytest.fixture
def hass():
    from conftest import FakeHass

    fake = FakeHass()
    fake.data = {}
    fake.config_entries = MagicMock()
    return fake


@pytest.fixture
def entry():
    return SimpleNamespace(
        entry_id="abc",
        data={
            "username": "user@proton.me",
            "uid": "uid-1",
            "access_token": "access-old",
            "refresh_token": "refresh-old",
            "scope": ["full", "self"],
        },
        options={},
    )


@pytest.mark.asyncio
async def test_async_refresh_persists_new_tokens(hass, entry):
    client = MagicMock()
    client.refresh.return_value = _session(
        access_token="access-new", refresh_token="refresh-new"
    )
    manager = ProtonSessionManager(hass, entry, client=client)

    updated = await manager.async_refresh()
    assert updated.access_token == "access-new"
    hass.config_entries.async_update_entry.assert_called_once()
    _, kwargs = hass.config_entries.async_update_entry.call_args
    assert kwargs["data"][CONF_ACCESS_TOKEN] == "access-new"
    assert kwargs["data"][CONF_REFRESH_TOKEN] == "refresh-new"


@pytest.mark.asyncio
async def test_async_refresh_preserves_existing_wireguard_fields(hass, entry):
    entry.data["wg_device_name"] = "ha-wg-proton"
    entry.data["wg_serial_number"] = "sn-keep"
    client = MagicMock()
    client.refresh.return_value = _session(
        access_token="access-new", refresh_token="refresh-new"
    )
    manager = ProtonSessionManager(hass, entry, client=client)

    await manager.async_refresh()
    _, kwargs = hass.config_entries.async_update_entry.call_args
    assert kwargs["data"]["wg_device_name"] == "ha-wg-proton"
    assert kwargs["data"]["wg_serial_number"] == "sn-keep"
    assert kwargs["data"][CONF_ACCESS_TOKEN] == "access-new"


@pytest.mark.asyncio
async def test_async_refresh_raises_auth_failed(hass, entry):
    client = MagicMock()
    client.refresh.side_effect = InvalidCredentials("expired")
    manager = ProtonSessionManager(hass, entry, client=client)
    with pytest.raises(ConfigEntryAuthFailed):
        await manager.async_refresh()


@pytest.mark.asyncio
async def test_async_setup_refreshes_and_schedules(hass, entry):
    client = MagicMock()
    client.refresh.return_value = _session(
        access_token="access-new", refresh_token="refresh-new"
    )
    client.data = _session(access_token="access-new", refresh_token="refresh-new")
    manager = ProtonSessionManager(
        hass, entry, client=client, refresh_interval=timedelta(hours=1)
    )
    await manager.async_setup()
    assert manager.data.access_token == "access-new"
    assert hass.config_entries.async_update_entry.called
    assert len(hass.data["_interval_callbacks"]) == 2
    intervals = {item[1] for item in hass.data["_interval_callbacks"]}
    assert timedelta(hours=1) in intervals
    await manager.async_unload()
    assert hass.data["_interval_callbacks"] == []
    await manager.async_unload()  # idempotent when already unloaded


@pytest.mark.asyncio
async def test_scheduled_refresh_invokes_refresh(hass, entry):
    client = MagicMock()
    client.refresh.return_value = _session(
        access_token="access-new", refresh_token="refresh-new"
    )
    manager = ProtonSessionManager(hass, entry, client=client)
    await manager._async_scheduled_refresh()
    client.refresh.assert_called_once()


@pytest.mark.asyncio
async def test_async_provision_wireguard_stores_slots(hass, entry):
    from unittest.mock import patch

    from proton_mikrotik_wg.wg_credentials import WireGuardCredential

    client = MagicMock()
    client.data = _session()
    client.live_session.return_value = MagicMock()
    slots = {
        1: WireGuardCredential(
            device_name="ha-wg-proton-1-stamp",
            serial_number="sn-1",
            client_private_key="sk==",
            client_public_key="pk==",
            server_public_key="spk==",
            endpoint_host="1.2.3.4",
            endpoint_port=51820,
            client_address="10.2.0.2/32",
            expiration_time=1,
            dns=None,
        )
    }
    hass.async_add_executor_job = AsyncMock(side_effect=lambda fn: fn())
    manager = ProtonSessionManager(hass, entry, client=client)

    with patch(
        "proton_mikrotik_wg.session_manager.provision_wireguard_slots",
        return_value=slots,
    ) as provision:
        result = await manager.async_provision_wireguard()

    assert result is slots
    assert provision.call_args.kwargs["count"] == 3  # default tunnel_count
    # Full provision resets refresh stamp + stores slots (last update wins for data).
    assert hass.config_entries.async_update_entry.called
    data_calls = [
        c.kwargs
        for c in hass.config_entries.async_update_entry.call_args_list
        if "data" in c.kwargs
    ]
    assert data_calls[-1]["data"]["wg_slots"][0]["wg_serial_number"] == "sn-1"
    options_calls = [
        c.kwargs
        for c in hass.config_entries.async_update_entry.call_args_list
        if "options" in c.kwargs
    ]
    assert options_calls
    assert "wg_refresh_last_at" in options_calls[-1]["options"]


@pytest.mark.asyncio
async def test_async_provision_wireguard_passes_exit_country(hass, entry):
    from unittest.mock import patch

    from proton_mikrotik_wg.const import CONF_VPN_EXIT_COUNTRY
    from proton_mikrotik_wg.wg_credentials import WireGuardCredential

    entry.options = {CONF_VPN_EXIT_COUNTRY: "GB"}
    client = MagicMock()
    client.data = _session()
    client.live_session.return_value = MagicMock()
    hass.async_add_executor_job = AsyncMock(side_effect=lambda fn: fn())
    manager = ProtonSessionManager(hass, entry, client=client)
    slots = {
        1: WireGuardCredential(
            device_name="ha-wg-proton-1-stamp",
            serial_number="sn-1",
            client_private_key="sk==",
            client_public_key="pk==",
            server_public_key="spk==",
            endpoint_host="1.2.3.4",
            endpoint_port=51820,
            client_address="10.2.0.2/32",
            expiration_time=1,
            dns=None,
        )
    }
    with patch(
        "proton_mikrotik_wg.session_manager.provision_wireguard_slots",
        return_value=slots,
    ) as provision:
        await manager.async_provision_wireguard()
    assert provision.call_args.kwargs["exit_country"] == "GB"


@pytest.mark.asyncio
async def test_async_provision_wireguard_one_slot_does_not_reset_stamp(hass, entry):
    from unittest.mock import patch

    from proton_mikrotik_wg.const import CONF_WG_REFRESH_LAST_AT
    from proton_mikrotik_wg.wg_credentials import WireGuardCredential

    entry.options = {CONF_WG_REFRESH_LAST_AT: 12345}
    client = MagicMock()
    client.data = _session()
    client.live_session.return_value = MagicMock()
    hass.async_add_executor_job = AsyncMock(side_effect=lambda fn: fn())
    manager = ProtonSessionManager(hass, entry, client=client)
    slots = {
        2: WireGuardCredential(
            device_name="ha-wg-proton-2-stamp",
            serial_number="sn-2",
            client_private_key="sk==",
            client_public_key="pk==",
            server_public_key="spk==",
            endpoint_host="2.2.2.2",
            endpoint_port=51820,
            client_address="10.2.0.2/32",
            expiration_time=1,
            dns=None,
        )
    }
    with patch(
        "proton_mikrotik_wg.session_manager.provision_wireguard_slots",
        return_value=slots,
    ) as provision:
        await manager.async_provision_wireguard(slot=2)
    assert provision.call_args.kwargs["slot"] == 2
    options_calls = [
        c.kwargs
        for c in hass.config_entries.async_update_entry.call_args_list
        if "options" in c.kwargs
    ]
    assert options_calls == []


@pytest.mark.asyncio
async def test_async_refresh_due_slots_renews_missed_and_applies(hass, entry):
    from unittest.mock import patch

    from proton_mikrotik_wg.const import (
        CONF_MIKROTIK_HOST,
        CONF_MIKROTIK_PASSWORD,
        CONF_MIKROTIK_USERNAME,
        CONF_MIKROTIK_WAN_GATEWAY,
        CONF_TUNNEL_COUNT,
        CONF_WG_REFRESH_INTERVAL,
        CONF_WG_REFRESH_LAST_AT,
        WG_REFRESH_DAILY,
    )
    from proton_mikrotik_wg.wg_credentials import WireGuardCredential

    def _slot(n: int, exp: int) -> WireGuardCredential:
        return WireGuardCredential(
            device_name=f"ha-wg-proton-{n}-x",
            serial_number=f"sn-{n}",
            client_private_key="sk==",
            client_public_key="pk==",
            server_public_key="spk==",
            endpoint_host=f"{n}.1.1.1",
            endpoint_port=51820,
            client_address="10.2.0.2/32",
            expiration_time=exp,
        )

    entry.options = {
        CONF_MIKROTIK_HOST: "10.0.20.1",
        CONF_MIKROTIK_USERNAME: "admin",
        CONF_MIKROTIK_PASSWORD: "secret",
        CONF_MIKROTIK_WAN_GATEWAY: "zen",
        CONF_TUNNEL_COUNT: 3,
        CONF_WG_REFRESH_INTERVAL: WG_REFRESH_DAILY,
        CONF_WG_REFRESH_LAST_AT: 1_000_000,
    }
    entry.data["wg_slots"] = [
        {
            "slot": 1,
            "wg_device_name": "ha-wg-proton-1-x",
            "wg_serial_number": "sn-1",
            "wg_client_private_key": "sk==",
            "wg_client_public_key": "pk==",
            "wg_server_public_key": "spk==",
            "wg_endpoint_host": "1.1.1.1",
            "wg_endpoint_port": 51820,
            "wg_client_address": "10.2.0.2/32",
            "wg_expiration_time": 300,
        },
        {
            "slot": 2,
            "wg_device_name": "ha-wg-proton-2-x",
            "wg_serial_number": "sn-2",
            "wg_client_private_key": "sk==",
            "wg_client_public_key": "pk==",
            "wg_server_public_key": "spk==",
            "wg_endpoint_host": "2.2.2.2",
            "wg_endpoint_port": 51820,
            "wg_client_address": "10.2.0.2/32",
            "wg_expiration_time": 100,
        },
        {
            "slot": 3,
            "wg_device_name": "ha-wg-proton-3-x",
            "wg_serial_number": "sn-3",
            "wg_client_private_key": "sk==",
            "wg_client_public_key": "pk==",
            "wg_server_public_key": "spk==",
            "wg_endpoint_host": "3.3.3.3",
            "wg_endpoint_port": 51820,
            "wg_client_address": "10.2.0.2/32",
            "wg_expiration_time": 200,
        },
    ]
    client = MagicMock()
    client.data = _session()
    client.live_session.return_value = MagicMock()
    hass.async_add_executor_job = AsyncMock(side_effect=lambda fn: fn())
    manager = ProtonSessionManager(hass, entry, client=client)

    async def fake_provision(*, slot=None):
        assert slot in (2, 3)
        return {slot: _slot(slot, 999)}

    with (
        patch("proton_mikrotik_wg.session_manager.time.time", return_value=1_000_000 + 2 * 86400 + 10),
        patch.object(manager, "async_provision_wireguard", side_effect=fake_provision) as provision,
        patch.object(manager, "async_apply_wireguard", new_callable=AsyncMock) as apply,
    ):
        await manager.async_refresh_due_slots()

    assert [c.kwargs.get("slot") for c in provision.await_args_list] == [2, 3]
    apply.assert_awaited_once()
    options_calls = [
        c.kwargs["options"]
        for c in hass.config_entries.async_update_entry.call_args_list
        if "options" in c.kwargs
    ]
    assert options_calls[-1][CONF_WG_REFRESH_LAST_AT] == 1_000_000 + 2 * 86400


@pytest.mark.asyncio
async def test_async_refresh_due_slots_noop_when_not_due(hass, entry):
    from unittest.mock import patch

    from proton_mikrotik_wg.const import (
        CONF_MIKROTIK_HOST,
        CONF_MIKROTIK_PASSWORD,
        CONF_MIKROTIK_USERNAME,
        CONF_MIKROTIK_WAN_GATEWAY,
        CONF_WG_REFRESH_LAST_AT,
    )

    entry.options = {
        CONF_MIKROTIK_HOST: "10.0.20.1",
        CONF_MIKROTIK_USERNAME: "admin",
        CONF_MIKROTIK_PASSWORD: "secret",
        CONF_MIKROTIK_WAN_GATEWAY: "zen",
        CONF_WG_REFRESH_LAST_AT: 1_000_000,
    }
    entry.data["wg_slots"] = [
        {
            "slot": 1,
            "wg_device_name": "ha-wg-proton-1-x",
            "wg_serial_number": "sn-1",
            "wg_client_private_key": "sk==",
            "wg_client_public_key": "pk==",
            "wg_server_public_key": "spk==",
            "wg_endpoint_host": "1.1.1.1",
            "wg_endpoint_port": 51820,
            "wg_client_address": "10.2.0.2/32",
            "wg_expiration_time": 100,
        }
    ]
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    with (
        patch("proton_mikrotik_wg.session_manager.time.time", return_value=1_000_100),
        patch.object(manager, "async_provision_wireguard", new_callable=AsyncMock) as provision,
    ):
        await manager.async_refresh_due_slots()
    provision.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_setup_initializes_refresh_stamp_without_renew(hass, entry):
    from unittest.mock import patch

    from proton_mikrotik_wg.const import CONF_WG_REFRESH_LAST_AT

    entry.data["wg_slots"] = [
        {
            "slot": 1,
            "wg_device_name": "ha-wg-proton-1-x",
            "wg_serial_number": "sn-1",
            "wg_client_private_key": "sk==",
            "wg_client_public_key": "pk==",
            "wg_server_public_key": "spk==",
            "wg_endpoint_host": "1.1.1.1",
            "wg_endpoint_port": 51820,
            "wg_client_address": "10.2.0.2/32",
            "wg_expiration_time": 100,
        }
    ]
    client = MagicMock()
    client.refresh.return_value = _session()
    client.data = _session()
    manager = ProtonSessionManager(hass, entry, client=client)
    with (
        patch("proton_mikrotik_wg.session_manager.time.time", return_value=5_000),
        patch.object(manager, "async_refresh_due_slots", new_callable=AsyncMock) as due,
    ):
        await manager.async_setup()
    options_calls = [
        c.kwargs["options"]
        for c in hass.config_entries.async_update_entry.call_args_list
        if "options" in c.kwargs
    ]
    assert options_calls[0][CONF_WG_REFRESH_LAST_AT] == 5_000
    due.assert_awaited_once()
    await manager.async_unload()


@pytest.mark.asyncio
async def test_async_refresh_due_slots_failure_leaves_stamp(hass, entry):
    from unittest.mock import patch

    from proton_mikrotik_wg.const import (
        CONF_MIKROTIK_HOST,
        CONF_MIKROTIK_PASSWORD,
        CONF_MIKROTIK_USERNAME,
        CONF_MIKROTIK_WAN_GATEWAY,
        CONF_WG_REFRESH_INTERVAL,
        CONF_WG_REFRESH_LAST_AT,
        WG_REFRESH_DAILY,
    )

    entry.options = {
        CONF_MIKROTIK_HOST: "10.0.20.1",
        CONF_MIKROTIK_USERNAME: "admin",
        CONF_MIKROTIK_PASSWORD: "secret",
        CONF_MIKROTIK_WAN_GATEWAY: "zen",
        CONF_WG_REFRESH_INTERVAL: WG_REFRESH_DAILY,
        CONF_WG_REFRESH_LAST_AT: 1_000_000,
    }
    entry.data["wg_slots"] = [
        {
            "slot": 1,
            "wg_device_name": "ha-wg-proton-1-x",
            "wg_serial_number": "sn-1",
            "wg_client_private_key": "sk==",
            "wg_client_public_key": "pk==",
            "wg_server_public_key": "spk==",
            "wg_endpoint_host": "1.1.1.1",
            "wg_endpoint_port": 51820,
            "wg_client_address": "10.2.0.2/32",
            "wg_expiration_time": 100,
        }
    ]
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    with (
        patch(
            "proton_mikrotik_wg.session_manager.time.time",
            return_value=1_000_000 + 86400 + 1,
        ),
        patch.object(
            manager,
            "async_provision_wireguard",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ),
    ):
        assert await manager.async_refresh_due_slots() == 0
    assert entry.options[CONF_WG_REFRESH_LAST_AT] == 1_000_000


@pytest.mark.asyncio
async def test_async_refresh_due_slots_skips_when_already_running(hass, entry):
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    manager._wg_refresh_running = True
    assert await manager.async_refresh_due_slots() == 0


@pytest.mark.asyncio
async def test_scheduled_wg_refresh_invokes_due_slots(hass, entry):
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    manager.async_refresh_due_slots = AsyncMock(return_value=0)
    await manager._async_scheduled_wg_refresh()
    manager.async_refresh_due_slots.assert_awaited_once()


def test_wg_refresh_interval_defaults_monthly(hass, entry):
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    assert manager.wg_refresh_interval() == "monthly"
    entry.options = {"wg_refresh_interval": "  "}
    assert manager.wg_refresh_interval() == "monthly"


@pytest.mark.asyncio
async def test_async_refresh_due_slots_skips_without_mikrotik_or_slots(hass, entry):
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    assert await manager.async_refresh_due_slots() == 0
    entry.options = {
        "mikrotik_host": "10.0.20.1",
        "mikrotik_username": "admin",
        "mikrotik_password": "secret",
        "mikrotik_wan_gateway": "zen",
        "wg_refresh_last_at": 1,
    }
    assert await manager.async_refresh_due_slots() == 0


@pytest.mark.asyncio
async def test_async_ensure_stamp_noop_when_present_or_no_slots(hass, entry):
    from proton_mikrotik_wg.const import CONF_WG_REFRESH_LAST_AT

    entry.options = {CONF_WG_REFRESH_LAST_AT: 9}
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    await manager._async_ensure_wg_refresh_stamp()
    assert hass.config_entries.async_update_entry.call_count == 0

    entry.options = {}
    await manager._async_ensure_wg_refresh_stamp()
    assert hass.config_entries.async_update_entry.call_count == 0


@pytest.mark.asyncio
async def test_async_refresh_due_slots_skips_without_last_at(hass, entry):
    entry.options = {
        "mikrotik_host": "10.0.20.1",
        "mikrotik_username": "admin",
        "mikrotik_password": "secret",
        "mikrotik_wan_gateway": "zen",
    }
    entry.data["wg_slots"] = [
        {
            "slot": 1,
            "wg_device_name": "ha-wg-proton-1-x",
            "wg_serial_number": "sn-1",
            "wg_client_private_key": "sk==",
            "wg_client_public_key": "pk==",
            "wg_server_public_key": "spk==",
            "wg_endpoint_host": "1.1.1.1",
            "wg_endpoint_port": 51820,
            "wg_client_address": "10.2.0.2/32",
            "wg_expiration_time": 100,
        }
    ]
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    assert await manager.async_refresh_due_slots() == 0


@pytest.mark.asyncio
async def test_update_options_and_data_skip_non_dict_containers(hass):
    from types import MappingProxyType
    from unittest.mock import patch

    from proton_mikrotik_wg.wg_credentials import WireGuardCredential

    entry = SimpleNamespace(
        entry_id="abc",
        options=MappingProxyType({}),
        data=MappingProxyType(
            {
                "username": "user@proton.me",
                "uid": "uid-1",
                "access_token": "access-old",
                "refresh_token": "refresh-old",
                "scope": ["full", "self"],
            }
        ),
    )
    hass.config_entries = MagicMock()
    hass.async_add_executor_job = AsyncMock(side_effect=lambda fn: fn())
    client = MagicMock()
    client.data = _session()
    client.live_session.return_value = MagicMock()
    manager = ProtonSessionManager(hass, entry, client=client)
    manager._update_options(wg_refresh_last_at=1)

    slots = {
        1: WireGuardCredential(
            device_name="ha-wg-proton-1-x",
            serial_number="sn-1",
            client_private_key="sk==",
            client_public_key="pk==",
            server_public_key="spk==",
            endpoint_host="1.1.1.1",
            endpoint_port=51820,
            client_address="10.2.0.2/32",
            expiration_time=1,
        )
    }
    with patch(
        "proton_mikrotik_wg.session_manager.provision_wireguard_slots",
        return_value=slots,
    ):
        await manager.async_provision_wireguard(slot=1)
    hass.config_entries.async_update_entry.assert_called()
