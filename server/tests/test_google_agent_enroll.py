"""Agent Google enrollment: POST /agent/google-enroll."""
from unittest import mock

import pytest

from server.app import google_auth


def test_google_enroll_creates_user_and_device(client):
    fake_payload = {
        "sub": "google-sub-789",
        "email": "bob@example.com",
        "email_verified": True,
        "name": "Bob",
        "picture": "https://example.com/bob.jpg",
    }
    with mock.patch.object(google_auth, "verify_id_token", return_value=fake_payload):
        r = client.post(
            "/api/v1/agent/google-enroll",
            json={
                "id_token": "fake-token",
                "device_uid": "DESKTOP-XYZ",
                "device_name": "Bob's PC",
            },
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_email"] == "bob@example.com"
    assert body["device_uid"] == "DESKTOP-XYZ"
    assert body["device_name"] == "Bob's PC"
    assert len(body["device_token"]) > 20  # token plain returnat


def test_google_enroll_relinks_existing_device(client):
    fake_payload = {
        "sub": "google-sub-carol",
        "email": "carol@example.com",
        "email_verified": True,
        "name": "Carol",
        "picture": None,
    }
    with mock.patch.object(google_auth, "verify_id_token", return_value=fake_payload):
        # Prima inrolare
        r1 = client.post(
            "/api/v1/agent/google-enroll",
            json={"id_token": "t", "device_uid": "UID-1", "device_name": "PC1"},
        )
        token1 = r1.json()["device_token"]

        # A doua inrolare (acelasi UID) — token nou
        r2 = client.post(
            "/api/v1/agent/google-enroll",
            json={"id_token": "t", "device_uid": "UID-1", "device_name": "PC1"},
        )
        token2 = r2.json()["device_token"]

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert token1 != token2  # token re-emis (relink)


def test_google_enroll_rejects_invalid_token(client):
    with mock.patch.object(
        google_auth, "verify_id_token",
        side_effect=google_auth.GoogleAuthError("invalid"),
    ):
        r = client.post(
            "/api/v1/agent/google-enroll",
            json={"id_token": "bad", "device_uid": "UID", "device_name": "PC"},
        )
    assert r.status_code == 401
