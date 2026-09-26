from __future__ import annotations

import os

import pytest

from container_inspect.linux.capabilities import (
    CapabilityInspector,
)


def test_inspector_uses_current_process() -> None:
    inspector = CapabilityInspector(os.getpid())

    assert inspector.pid == os.getpid()


def test_process_exists() -> None:
    inspector = CapabilityInspector(os.getpid())

    assert inspector.exists() is True


def test_current_process_has_capabilities() -> None:
    inspector = CapabilityInspector(os.getpid())

    capabilities = inspector.capabilities()

    assert isinstance(capabilities, list)
    assert len(capabilities) > 0


def test_capability_names_are_strings() -> None:
    inspector = CapabilityInspector(os.getpid())

    capabilities = inspector.capabilities()

    for capability in capabilities:
        assert isinstance(capability.name, str)
        assert capability.name


def test_capability_values_are_integers() -> None:
    inspector = CapabilityInspector(os.getpid())

    capabilities = inspector.capabilities()

    for capability in capabilities:
        assert isinstance(capability.value, int)
        assert capability.value >= 0


def test_get_capability() -> None:
    inspector = CapabilityInspector(os.getpid())

    capability = inspector.get("CAP_CHOWN")

    if capability is not None:
        assert capability.name == "CAP_CHOWN"
        assert isinstance(capability.value, int)


def test_invalid_pid() -> None:
    with pytest.raises(ValueError):
        CapabilityInspector(0)


def test_negative_pid() -> None:
    with pytest.raises(ValueError):
        CapabilityInspector(-1)


def test_nonexistent_process() -> None:
    inspector = CapabilityInspector(999999999)

    assert inspector.exists() is False


def test_capabilities_for_nonexistent_process() -> None:
    inspector = CapabilityInspector(999999999)

    with pytest.raises(Exception):
        inspector.capabilities()