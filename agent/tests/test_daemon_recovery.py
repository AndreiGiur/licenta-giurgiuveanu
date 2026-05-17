"""Integration tests pentru flow-ul de recovery la 401 in daemon_loop."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent import core


def test_daemon_invalid_token_exits_after_first_401(monkeypatch):
    call_log = []
    def fake_heartbeat(*a, **kw):
        call_log.append("heartbeat")
        raise core.DeviceTokenInvalidError("HTTP 401: revoked")
    def fake_get_job(*a, **kw):
        call_log.append("get_job")
        return None

    monkeypatch.setattr(core, "api_heartbeat", fake_heartbeat)
    monkeypatch.setattr(core, "api_get_next_job", fake_get_job)

    triggered = []
    core.daemon_loop(
        "http://api", "uid", "tok",
        poll_interval=0, auto_interval=0,
        log=lambda m, s="info": None,
        should_stop=lambda: False,
        should_pause=lambda: False,
        on_token_invalid=lambda: triggered.append(True),
    )

    assert triggered == [True]
    # Doar primul heartbeat e apelat, nu si get_job (loop iese pe spot)
    assert call_log == ["heartbeat"]


def test_daemon_network_error_keeps_running(monkeypatch):
    """ConnectionError → ApiError → NU declanseaza on_token_invalid."""
    iter_count = [0]
    def fake_heartbeat(*a, **kw):
        iter_count[0] += 1
        raise core.ApiError("connection refused")

    monkeypatch.setattr(core, "api_heartbeat", fake_heartbeat)
    monkeypatch.setattr(core, "api_get_next_job", lambda *a, **kw: None)

    triggered = []
    core.daemon_loop(
        "http://api", "uid", "tok",
        poll_interval=0, auto_interval=0,
        log=lambda m, s="info": None,
        should_stop=lambda: iter_count[0] >= 5,
        should_pause=lambda: False,
        on_token_invalid=lambda: triggered.append(True),
    )

    assert triggered == []
    assert iter_count[0] >= 5


def test_daemon_get_job_401_also_triggers_recovery(monkeypatch):
    """Daca heartbeat e OK dar get_next_job da 401, recovery se declanseaza."""
    monkeypatch.setattr(core, "api_heartbeat", lambda *a, **kw: None)
    monkeypatch.setattr(core, "api_get_next_job",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            core.DeviceTokenInvalidError("HTTP 401: bad")))

    triggered = []
    core.daemon_loop(
        "http://api", "uid", "tok",
        poll_interval=0, auto_interval=0,
        log=lambda m, s="info": None,
        should_stop=lambda: False,
        should_pause=lambda: False,
        on_token_invalid=lambda: triggered.append(True),
    )

    assert triggered == [True]
