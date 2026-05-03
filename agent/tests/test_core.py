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
