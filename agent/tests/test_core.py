"""Smoke tests pentru agent/core.py.

Verificam ca refactor-ul nu a stricat partile pure (fara network):
- citire/scriere config in tmp dir
- collect_system_data nu arunca
- helper-ele de packaging
"""
import configparser
import os
from pathlib import Path
from unittest import mock

import pytest

from agent import core


@pytest.fixture
def tmp_config_dir(tmp_path, monkeypatch):
    """Pointam CONFIG_DIR / CONFIG_FILE in tmp_path ca testele sa nu murdareasca HOME."""
    monkeypatch.setattr(core, "CONFIG_DIR", tmp_path / ".vulnwatch")
    monkeypatch.setattr(core, "CONFIG_FILE", tmp_path / ".vulnwatch" / "config.ini")
    yield tmp_path


def test_is_enrolled_false_when_no_config(tmp_config_dir):
    assert core.is_enrolled() is False


def test_save_and_read_enrollment(tmp_config_dir):
    core.save_enrollment("http://api/v1", "host-1", "tok-abc-123")
    assert core.is_enrolled() is True

    api, uid, token = core.get_enrollment()
    assert api == "http://api/v1"
    assert uid == "host-1"
    assert token == "tok-abc-123"


def test_clear_config(tmp_config_dir):
    core.save_enrollment("http://api/v1", "host-1", "tok")
    assert core.is_enrolled() is True
    assert core.clear_config() is True
    assert core.is_enrolled() is False
    # Idempotent
    assert core.clear_config() is False


def test_get_enrollment_raises_when_missing(tmp_config_dir):
    with pytest.raises(RuntimeError):
        core.get_enrollment()


def test_collect_system_data_returns_well_formed_dict():
    """Smoke test — nu apelam network, doar verificam structura."""
    data = core.collect_system_data("test-host")
    assert data["device_uid"] == "test-host"
    assert "system" in data["os"]
    assert "is_admin" in data["os"]
    assert "open_ports" in data["network"]
    assert isinstance(data["processes"], list)
    assert isinstance(data["software"], list)


def test_executable_path_returns_path():
    p = core.executable_path()
    assert isinstance(p, Path)


def test_is_frozen_returns_bool():
    assert isinstance(core.is_frozen(), bool)


def test_perform_enrollment_propagates_api_error(tmp_config_dir):
    """Daca login esueaza si nu e 401, eroarea trebuie sa se propage."""
    with mock.patch.object(core, "api_login",
                           side_effect=core.ApiError("HTTP 500: server down")):
        with pytest.raises(core.ApiError):
            core.perform_enrollment("http://api/v1", "u@e.com", "pw12345678",
                                    "uid", "name")


def test_generate_device_token_returns_plain_and_hash():
    import hashlib
    plain, h = core.generate_device_token()
    assert isinstance(plain, str)
    assert len(plain) > 40  # token_urlsafe(48) ≈ 64 chars
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
    # Hash-ul corespunde token-ului
    assert hashlib.sha256(plain.encode("utf-8")).hexdigest() == h


def test_generate_device_token_is_random():
    pairs = [core.generate_device_token() for _ in range(5)]
    plains = {p for p, _ in pairs}
    hashes = {h for _, h in pairs}
    assert len(plains) == 5
    assert len(hashes) == 5


def test_request_with_device_token_raises_invalid_on_401(monkeypatch):
    import requests as _req

    class FakeResponse:
        status_code = 401
        text = '{"detail":"invalid device token"}'
        ok = False
        def json(self):
            return {"detail": "invalid device token"}

    monkeypatch.setattr(_req, "request", lambda method, url, **kw: FakeResponse())

    with pytest.raises(core.DeviceTokenInvalidError):
        core._request_with_device_token("GET", "http://x/foo", device_token="bad")


def test_request_with_device_token_raises_api_error_on_500(monkeypatch):
    import requests as _req

    class FakeResponse:
        status_code = 500
        text = "Internal Server Error"
        ok = False
        def json(self):
            raise ValueError()

    monkeypatch.setattr(_req, "request", lambda method, url, **kw: FakeResponse())

    with pytest.raises(core.ApiError):
        core._request_with_device_token("GET", "http://x/foo", device_token="any")


def test_api_create_device_sends_token_hash(monkeypatch):
    captured = {}
    def fake_request(method, url, json=None, headers=None, timeout=15):
        captured["json"] = json
        captured["url"] = url
        return {"id": 1, "device_uid": "uid-1", "name": "N", "created_at": "2026-01-01"}
    monkeypatch.setattr(core, "_request", fake_request)

    result = core.api_create_device("http://api", "sess", "uid-1", "Test", token_hash="a"*64)
    assert captured["json"]["token_hash"] == "a"*64
    assert captured["json"]["device_uid"] == "uid-1"


def test_daemon_loop_calls_on_token_invalid_and_exits(monkeypatch):
    invalid_called = []
    def fake_heartbeat(*a, **kw):
        raise core.DeviceTokenInvalidError("HTTP 401: invalid")

    monkeypatch.setattr(core, "api_heartbeat", fake_heartbeat)
    monkeypatch.setattr(core, "api_get_next_job", lambda *a, **kw: None)

    core.daemon_loop(
        "http://api", "uid-1", "token-1",
        poll_interval=0,
        log=lambda m, s="info": None,
        should_stop=lambda: False,
        should_pause=lambda: False,
        on_token_invalid=lambda: invalid_called.append(True),
    )

    assert invalid_called == [True]


def test_daemon_loop_continues_on_api_error(monkeypatch):
    call_count = [0]
    def fake_heartbeat(*a, **kw):
        call_count[0] += 1
        raise core.ApiError("connection refused")

    monkeypatch.setattr(core, "api_heartbeat", fake_heartbeat)
    monkeypatch.setattr(core, "api_get_next_job", lambda *a, **kw: None)

    invalid_called = []
    core.daemon_loop(
        "http://api", "uid", "tok",
        poll_interval=0,
        log=lambda m, s="info": None,
        should_stop=lambda: call_count[0] >= 3,
        should_pause=lambda: False,
        on_token_invalid=lambda: invalid_called.append(True),
    )

    # ApiError nu trebuie sa declanseze on_token_invalid
    assert invalid_called == []
    assert call_count[0] >= 3


def test_run_nmap_skipped_for_standard():
    """standard scan nu ruleaza niciodata nmap."""
    from agent import core
    result = core._run_nmap_if_needed({"scan_type": "standard"})
    assert result is None


def test_run_nmap_advanced_now_triggers_nmap(monkeypatch):
    """advanced acum ruleaza nmap (moderat). Daca nmap lipseste → {error: nmap_missing}."""
    from agent import core
    monkeypatch.setattr(core, "_nmap_path", lambda: None)
    result = core._run_nmap_if_needed({"scan_type": "advanced"})
    assert result == {"error": "nmap_missing"}


def test_run_nmap_deep_no_nmap_installed(monkeypatch):
    """deep fara nmap → {error: nmap_missing} (idem ca advanced)."""
    from agent import core
    monkeypatch.setattr(core, "_nmap_path", lambda: None)
    result = core._run_nmap_if_needed({"scan_type": "deep"})
    assert result == {"error": "nmap_missing"}


def test_run_nmap_if_deep_alias_still_works():
    """_run_nmap_if_deep e alias backwards-compat pentru _run_nmap_if_needed."""
    from agent import core
    assert core._run_nmap_if_deep is core._run_nmap_if_needed
