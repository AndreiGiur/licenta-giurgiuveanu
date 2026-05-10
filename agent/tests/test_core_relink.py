"""Smoke tests pentru helperii noi din core.py."""
import pytest
from unittest import mock

from agent import core


@pytest.fixture
def tmp_config(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "CONFIG_DIR", tmp_path / ".vulnwatch")
    monkeypatch.setattr(core, "CONFIG_FILE", tmp_path / ".vulnwatch" / "config.ini")
    yield tmp_path


def test_save_enrollment_with_metadata(tmp_config):
    core.save_enrollment("http://api/v1", "host-1", "tok-abc",
                         device_name="Friendly Name", user_email="u@e.com")
    meta = core.get_enrollment_meta()
    assert meta["device_name"] == "Friendly Name"
    assert meta["user_email"] == "u@e.com"

    api, uid, tok = core.get_enrollment()
    assert (api, uid, tok) == ("http://api/v1", "host-1", "tok-abc")


def test_save_enrollment_without_metadata_keeps_keys_empty(tmp_config):
    core.save_enrollment("http://api/v1", "host-1", "tok-abc")
    meta = core.get_enrollment_meta()
    assert meta["device_name"] == ""
    assert meta["user_email"] == ""


def test_get_enrollment_meta_when_no_config(tmp_config):
    meta = core.get_enrollment_meta()
    assert meta == {"device_name": "", "user_email": ""}


def test_login_or_register_falls_back_to_register():
    """Cand login da 401 si allow_create_account=True, incercam register-then-login."""
    with mock.patch.object(core, "api_login") as mlogin, \
         mock.patch.object(core, "api_register") as mreg:
        # Primul login esueaza cu 401
        mlogin.side_effect = [
            core.ApiError("HTTP 401: invalid credentials"),
            "session-tok-after-register",
        ]
        token = core.login_or_register("http://api", "u@e.com", "password123")
        assert token == "session-tok-after-register"
        mreg.assert_called_once_with("http://api", "u@e.com", "password123")


def test_login_or_register_propagates_non_401():
    """Erorile non-401 (server down, etc.) nu trebuie sa declanseze register."""
    with mock.patch.object(core, "api_login",
                           side_effect=core.ApiError("HTTP 500: server down")):
        with pytest.raises(core.ApiError):
            core.login_or_register("http://api", "u@e.com", "password123")


def test_api_get_device_by_uid_returns_none_on_404():
    """Wrap-er-ul converteste 404 in None (semnal de smart re-link disponibil)."""
    with mock.patch.object(core, "_request",
                           side_effect=core.ApiError("HTTP 404: device not found")):
        result = core.api_get_device_by_uid("http://api", "tok", "missing")
        assert result is None


def test_api_get_device_by_uid_propagates_other_errors():
    with mock.patch.object(core, "_request",
                           side_effect=core.ApiError("HTTP 500: server down")):
        with pytest.raises(core.ApiError):
            core.api_get_device_by_uid("http://api", "tok", "x")


def test_enroll_device_with_session_relink_path():
    """Daca relink_if_exists si exista device, sare la api_relink_device."""
    with mock.patch.object(core, "api_get_device_by_uid",
                           return_value={"device_uid": "h", "name": "Existing"}), \
         mock.patch.object(core, "api_relink_device",
                           return_value={"device_token": "new-tok",
                                         "device_uid": "h", "name": "Existing"}) as mrelink, \
         mock.patch.object(core, "api_create_device") as mcreate:
        result = core.enroll_device_with_session(
            "http://api", "sess", "h", "Existing", relink_if_exists=True,
        )
        assert result["device_token"] == "new-tok"
        mrelink.assert_called_once()
        mcreate.assert_not_called()


def test_enroll_device_with_session_create_path():
    """Daca relink_if_exists=False, mergem direct la create."""
    with mock.patch.object(core, "api_create_device",
                           return_value={"device_token": "tok",
                                         "device_uid": "h", "name": "New"}) as mcreate, \
         mock.patch.object(core, "api_get_device_by_uid") as mlookup, \
         mock.patch.object(core, "api_relink_device") as mrelink:
        result = core.enroll_device_with_session(
            "http://api", "sess", "h", "New", relink_if_exists=False,
        )
        assert result["device_token"] == "tok"
        mcreate.assert_called_once()
        mlookup.assert_not_called()
        mrelink.assert_not_called()
