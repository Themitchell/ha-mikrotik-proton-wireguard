"""Pytest fixtures shared across the suite."""

from __future__ import annotations

from typing import Any, Callable

import pytest

import ha_stubs

ha_stubs.install_homeassistant_stubs()


class FakeHass:
    """Runs executor jobs inline for unit tests."""

    async def async_add_executor_job(
        self, target: Callable[..., Any], *args: Any
    ) -> Any:
        return target(*args)


@pytest.fixture
def hass() -> FakeHass:
    return FakeHass()
