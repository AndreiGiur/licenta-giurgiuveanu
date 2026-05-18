"""Protocol IPC GUI↔Service.

Pe Windows folosim Named Pipe (`\\\\.\\pipe\\vulnwatch-status`) când serviciul
rulează ca LocalSystem. Pentru dev/testing și portabilitate folosim socket TCP
localhost. API-ul de mai jos abstractizează ambele cazuri.

Protocol: line-delimited JSON.
- Request: {"cmd": "status"} → Response: {"running": true, ...}
- Push event: {"event": "scan_done", "score": 42}
"""
from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any, Callable, Optional

IpcMessage = dict[str, Any]


PIPE_NAME = r"\\.\pipe\vulnwatch-status"
DEFAULT_TCP_PORT = 47815  # fallback dev port


def handle_message_default(msg: IpcMessage) -> dict:
    """Default handler — răspunde cu error pentru cmd necunoscut."""
    cmd = msg.get("cmd", "")
    if cmd == "ping":
        return {"ok": True, "pong": True}
    return {"error": f"unknown cmd: {cmd}"}


class IpcServer:
    """Server IPC. Pe Windows folosim named pipe via pywin32 dacă disponibil;
    altfel TCP socket (dev mode)."""

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_TCP_PORT,
                 handler: Callable[[IpcMessage], dict] = handle_message_default):
        self.host = host
        self.port = port
        self.handler = handler
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._subscribers: list[socket.socket] = []
        self._sub_lock = threading.Lock()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn,),
                             daemon=True).start()

    def _handle_client(self, conn: socket.socket) -> None:
        conn.settimeout(2.0)
        buffer = b""
        is_subscriber = False
        try:
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    if is_subscriber:
                        # Subscriber rămâne conectat — continuă să aștepte
                        continue
                    continue
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
                    if msg.get("cmd") == "subscribe_events":
                        with self._sub_lock:
                            self._subscribers.append(conn)
                        is_subscriber = True
                        self._send(conn, {"ok": True})
                        # Subscribers rămân conectați pentru push events —
                        # continuăm loop-ul, nu return, ca finally să ruleze la final
                    else:
                        response = self.handler(msg)
                        self._send(conn, response)
        finally:
            try:
                conn.close()
            except Exception:
                pass
            with self._sub_lock:
                if conn in self._subscribers:
                    self._subscribers.remove(conn)

    def _send(self, conn: socket.socket, msg: dict) -> None:
        try:
            conn.sendall((json.dumps(msg) + "\n").encode("utf-8"))
        except OSError:
            pass

    def broadcast_event(self, event: dict) -> None:
        """Trimite event către toți subscribers."""
        with self._sub_lock:
            stale = []
            for conn in self._subscribers:
                try:
                    conn.sendall((json.dumps(event) + "\n").encode("utf-8"))
                except OSError:
                    stale.append(conn)
            for conn in stale:
                self._subscribers.remove(conn)

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)


class IpcClient:
    """Client IPC. Conectare on-demand per request."""

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_TCP_PORT):
        self.host = host
        self.port = port
        self._sub_thread: Optional[threading.Thread] = None
        self._sub_stop = threading.Event()

    def request(self, msg: IpcMessage, timeout: float = 2.0) -> dict:
        with socket.create_connection((self.host, self.port), timeout=timeout) as s:
            s.sendall((json.dumps(msg) + "\n").encode("utf-8"))
            buffer = b""
            s.settimeout(timeout)
            while b"\n" not in buffer:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buffer += chunk
            line = buffer.split(b"\n", 1)[0]
            return json.loads(line.decode("utf-8"))

    def subscribe_events(self, callback: Callable[[dict], None]) -> None:
        """Pornește thread care primește evenimente push de la server."""
        def loop():
            try:
                with socket.create_connection((self.host, self.port),
                                              timeout=5.0) as s:
                    s.sendall(b'{"cmd":"subscribe_events"}\n')
                    s.settimeout(1.0)
                    buffer = b""
                    ack_received = False
                    while not self._sub_stop.is_set():
                        try:
                            chunk = s.recv(4096)
                        except socket.timeout:
                            continue
                        if not chunk:
                            break
                        buffer += chunk
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            if not line.strip():
                                continue
                            try:
                                msg = json.loads(line.decode("utf-8"))
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                continue
                            # Prima linie este ack-ul {"ok": true} — o ignorăm
                            if not ack_received:
                                ack_received = True
                                continue
                            callback(msg)
            except (OSError, socket.timeout):
                pass

        self._sub_thread = threading.Thread(target=loop, daemon=True)
        self._sub_thread.start()

    def unsubscribe(self) -> None:
        self._sub_stop.set()
