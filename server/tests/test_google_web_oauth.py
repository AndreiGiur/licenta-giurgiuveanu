"""Web OAuth flow: /auth/google/url + /auth/google/callback (mock Google)."""
from unittest import mock

import pytest

from server.app import google_auth


def test_google_url_returns_state_and_auth_url(client):
    r = client.get("/api/v1/auth/google/url")
    assert r.status_code == 200
    body = r.json()
    assert "auth_url" in body
    assert "state" in body
    assert "accounts.google.com" in body["auth_url"]
    assert f"state={body['state']}" in body["auth_url"]


def test_google_callback_creates_user_and_redirects(client):
    # 1. Cerere URL ca sa avem state-ul valid
    r = client.get("/api/v1/auth/google/url")
    state = r.json()["state"]

    fake_id_token = "fake.id.token"
    fake_payload = {
        "iss": "https://accounts.google.com",
        "sub": "google-sub-123",
        "email": "alice@example.com",
        "email_verified": True,
        "name": "Alice",
        "picture": "https://example.com/alice.jpg",
    }

    async def fake_exchange(**kwargs):
        return {"id_token": fake_id_token}

    with mock.patch.object(google_auth, "exchange_code_for_token", side_effect=fake_exchange), \
         mock.patch.object(google_auth, "verify_id_token", return_value=fake_payload):
        r = client.get(
            f"/api/v1/auth/google/callback?code=fake-code&state={state}",
            follow_redirects=False,
        )

    assert r.status_code in (302, 307)
    assert "/dashboard" in r.headers["location"]
    # Cookie de sesiune e setat
    assert "vw_session" in r.headers.get("set-cookie", "")

    # User-ul a fost creat
    r2 = client.get("/api/v1/auth/me")
    assert r2.status_code == 200
    me = r2.json()
    assert me["email"] == "alice@example.com"
    assert me["auth_provider"] == "google"
    assert me["google_picture_url"] == "https://example.com/alice.jpg"


def test_google_callback_invalid_state_rejected(client):
    r = client.get(
        "/api/v1/auth/google/callback?code=fake-code&state=bogus-state",
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_google_callback_links_existing_email_account(client, auth_client):
    """Un cont existent cu email/parola devine 'both' dupa login cu Google la acelasi email."""
    email = auth_client["email"]

    # Cerere URL noua (sesiune curata)
    r = client.get("/api/v1/auth/google/url")
    state = r.json()["state"]

    fake_payload = {
        "iss": "https://accounts.google.com",
        "sub": "google-sub-456",
        "email": email,
        "email_verified": True,
        "name": "Existing User",
        "picture": "https://example.com/x.jpg",
    }

    async def fake_exchange(**kwargs):
        return {"id_token": "fake-token"}

    with mock.patch.object(google_auth, "exchange_code_for_token", side_effect=fake_exchange), \
         mock.patch.object(google_auth, "verify_id_token", return_value=fake_payload):
        r = client.get(
            f"/api/v1/auth/google/callback?code=fake-code&state={state}",
            follow_redirects=False,
        )

    assert r.status_code in (302, 307)

    # Verifica ca user-ul existent a primit auth_provider=both si google_sub
    r2 = client.get("/api/v1/auth/me")
    me = r2.json()
    assert me["email"] == email
    assert me["auth_provider"] == "both"
