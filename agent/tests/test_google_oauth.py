"""Test api_google_enroll cu mock HTTP."""
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent import core


def test_api_google_enroll_sends_token_hash():
    """Backend nu mai returneaza device_token. Clientul trimite token_hash."""
    fake_response = {
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
            token_hash="a" * 64,
        )
    assert result["user_email"] == "test@example.com"
    m.assert_called_once()
    args, kwargs = m.call_args
    assert args[0] == "POST"
    assert "/agent/google-enroll" in args[1]
    assert kwargs["json"]["id_token"] == "fake-id-token"
    assert kwargs["json"]["token_hash"] == "a" * 64


def test_api_google_enroll_propagates_api_error():
    with mock.patch.object(core, "_request", side_effect=core.ApiError("401")):
        with pytest.raises(core.ApiError):
            core.api_google_enroll("http://api", "bad", "uid", "name",
                                   token_hash="b" * 64)
