"""Tests pentru protocolul IPC GUI↔Service.
Folosim socket TCP localhost ca substitut pentru named pipe (portabilitate CI),
dar API-ul este abstractizat în ipc.py să folosească named pipe pe Windows.
"""
import json
import threading
import time
import socket
from contextlib import closing

import pytest

from agent.ipc import (
    IpcServer, IpcClient, IpcMessage,
    handle_message_default,
)


@pytest.fixture
def server_port():
    """Alege un port liber pentru fiecare test."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    # Pe Windows SO_REUSEADDR nu permite două socket-uri să bind același port
    # simultan, deci eliberăm portul înainte de yield.
    yield port


def test_status_cmd_returns_dict(server_port):
    """Client trimite {cmd:status}, Server răspunde cu starea."""
    handler_calls = []

    def handler(msg: IpcMessage) -> dict:
        handler_calls.append(msg)
        if msg.get("cmd") == "status":
            return {"running": True, "paused": False, "last_heartbeat": 1000}
        return {"error": "unknown"}

    server = IpcServer(host="127.0.0.1", port=server_port, handler=handler)
    server.start()
    time.sleep(0.1)

    try:
        client = IpcClient(host="127.0.0.1", port=server_port)
        response = client.request({"cmd": "status"})
        assert response["running"] is True
        assert response["last_heartbeat"] == 1000
        assert len(handler_calls) == 1
        assert handler_calls[0]["cmd"] == "status"
    finally:
        server.stop()


def test_push_event_to_client(server_port):
    """Server poate emite evenimente push (scan_done, token_invalid)."""
    received = []

    server = IpcServer(host="127.0.0.1", port=server_port,
                       handler=lambda msg: {"ok": True})
    server.start()
    time.sleep(0.1)

    client = IpcClient(host="127.0.0.1", port=server_port)
    client.subscribe_events(lambda evt: received.append(evt))
    time.sleep(0.1)

    server.broadcast_event({"event": "scan_done", "score": 42})
    time.sleep(0.2)

    server.stop()
    assert len(received) == 1
    assert received[0]["event"] == "scan_done"
    assert received[0]["score"] == 42


def test_unknown_cmd_returns_error(server_port):
    server = IpcServer(host="127.0.0.1", port=server_port,
                       handler=handle_message_default)
    server.start()
    time.sleep(0.1)
    try:
        client = IpcClient(host="127.0.0.1", port=server_port)
        response = client.request({"cmd": "bogus"})
        assert "error" in response
    finally:
        server.stop()
