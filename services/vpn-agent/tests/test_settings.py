from pathlib import PurePosixPath

import pytest
from pydantic import ValidationError

from nebula_agent.settings import Settings


def test_xray_cannot_be_enabled_before_delivery_milestone() -> None:
    with pytest.raises(ValidationError, match="Xray is disabled"):
        Settings(xray_enabled=True)


def test_host_paths_must_be_absolute() -> None:
    with pytest.raises(ValidationError, match="host paths must be absolute"):
        Settings(xray_binary=PurePosixPath("bin/xray"))


def test_invalid_interface_name_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Linux interface"):
        Settings(wg_interface="wg0; shutdown")


def test_unknown_explicit_setting_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        Settings(command="id")  # type: ignore[call-arg]
