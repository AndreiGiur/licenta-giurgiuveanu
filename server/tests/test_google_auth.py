"""Verificare id_token + exchange code cu Google (mocked)."""
from unittest import mock

import pytest

from server.app import google_auth


def test_verify_id_token_returns_payload_when_valid():
    fake_payload = {
        "iss": "https://accounts.google.com",
        "sub": "1234567890",
        "email": "test@example.com",
        "email_verified": True,
        "name": "Test User",
        "picture": "https://example.com/pic.jpg",
    }
    with mock.patch("server.app.google_auth.id_token.verify_oauth2_token",
                    return_value=fake_payload):
        result = google_auth.verify_id_token("fake-token", "fake-client-id")
    assert result["email"] == "test@example.com"
    assert result["sub"] == "1234567890"


def test_verify_id_token_raises_on_invalid():
    with mock.patch("server.app.google_auth.id_token.verify_oauth2_token",
                    side_effect=ValueError("invalid token")):
        with pytest.raises(google_auth.GoogleAuthError):
            google_auth.verify_id_token("bad-token", "fake-client-id")


@pytest.mark.asyncio
async def test_exchange_code_returns_id_token():
    fake_resp = {
        "id_token": "fake.id.token",
        "access_token": "fake-access",
        "token_type": "Bearer",
    }
    with mock.patch("httpx.AsyncClient.post") as mock_post:
        mock_post.return_value = mock.MagicMock(
            status_code=200,
            json=mock.MagicMock(return_value=fake_resp),
            raise_for_status=mock.MagicMock(),
        )
        result = await google_auth.exchange_code_for_token(
            code="fake-code",
            client_id="client",
            client_secret="secret",
            redirect_uri="http://127.0.0.1/cb",
        )
    assert result["id_token"] == "fake.id.token"
