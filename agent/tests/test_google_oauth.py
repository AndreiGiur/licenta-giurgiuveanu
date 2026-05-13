"""Test api_google_enroll cu mock HTTP."""
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent import core


def test_api_google_enroll_returns_device_token():
    fake_response = {
        "device_token": "vw-abc123",
        "device_uid": "DESKTOP-Z",
        "device_name": "Test PC",
        "user_email": "test@example.com",
    }
    with mock.patch.object(core, "_request", return_value=fake_response) as m:
        result = core.api_google_enroll(
            api_base="http://api/v1",
            id_token="fake-id-token",
            device_uid="DESKTOP-Z",
            device_name="Test PC",
        )
    assert result["device_token"] == "vw-abc123"
    assert result["user_email"] == "test@example.com"
    m.assert_called_once()
    args, kwargs = m.call_args
    assert args[0] == "POST"
    assert "/agent/google-enroll" in args[1]
    assert kwargs["json"]["id_token"] == "fake-id-token"


def test_api_google_enroll_propagates_api_error():
    with mock.patch.object(core, "_request", side_effect=core.ApiError("401")):
        with pytest.raises(core.ApiError):
            core.api_google_enroll("http://api", "bad", "uid", "name")
