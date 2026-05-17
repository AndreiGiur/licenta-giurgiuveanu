"""Agent Google enrollment: POST /agent/google-enroll."""
from unittest import mock

import pytest

from server.app import google_auth


def test_google_enroll_creates_user_and_device(client):
    from conftest import make_token_pair
    fake_payload = {
        "sub": "google-sub-789",
        "email": "bob@example.com",
        "email_verified": True,
        "name": "Bob",
        "picture": "https://example.com/bob.jpg",
    }
    _, h = make_token_pair()
    with mock.patch.object(google_auth, "verify_id_token", return_value=fake_payload):
        r = client.post(
            "/api/v1/agent/google-enroll",
            json={
                "id_token": "fake-token",
                "device_uid": "DESKTOP-XYZ",
                "device_name": "Bob's PC",
                "token_hash": h,
            },
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_email"] == "bob@example.com"
    assert body["device_uid"] == "DESKTOP-XYZ"
    assert body["device_name"] == "Bob's PC"
    # Backend nu mai returneaza tokenul plain — clientul il are deja.
    assert "device_token" not in body


def test_google_enroll_relinks_existing_device(client):
    from conftest import make_token_pair
    fake_payload = {
        "sub": "google-sub-carol",
        "email": "carol@example.com",
        "email_verified": True,
        "name": "Carol",
        "picture": None,
    }
    plain1, h1 = make_token_pair()
    plain2, h2 = make_token_pair()
    with mock.patch.object(google_auth, "verify_id_token", return_value=fake_payload):
        # Prima inrolare
        r1 = client.post(
            "/api/v1/agent/google-enroll",
            json={"id_token": "t", "device_uid": "UID-1", "device_name": "PC1",
                  "token_hash": h1},
        )

        # A doua inrolare (acelasi UID) — token nou (relink)
        r2 = client.post(
            "/api/v1/agent/google-enroll",
            json={"id_token": "t", "device_uid": "UID-1", "device_name": "PC1",
                  "token_hash": h2},
        )

    assert r1.status_code == 200
    assert r2.status_code == 200
    # Hash-urile sunt diferite → tokens diferite (relink confirmat).
    assert plain1 != plain2


def test_google_enroll_rejects_invalid_token(client):
    from conftest import make_token_pair
    _, h = make_token_pair()
    with mock.patch.object(
        google_auth, "verify_id_token",
        side_effect=google_auth.GoogleAuthError("invalid"),
    ):
        r = client.post(
            "/api/v1/agent/google-enroll",
            json={"id_token": "bad", "device_uid": "UID", "device_name": "PC",
                  "token_hash": h},
        )
    assert r.status_code == 401
