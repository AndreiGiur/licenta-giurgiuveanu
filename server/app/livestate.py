"""Ring-buffer in-memory pentru traficul de retea live per device.

Date efemere de tip 'live monitor' — se pierd la restart backend (acceptabil,
nu e istoric de pastrat). Capat la 60 sample-uri/device (~10 min la 10s).
Thread-safe (heartbeat-urile pot veni concurent).
"""
from __future__ import annotations

from collections import deque
from threading import Lock

MAX_SAMPLES = 60

# device_id -> deque de sample-uri {ts, sent_rate_kbps, recv_rate_kbps, conn_count}
_buffers: dict[int, deque] = {}
# device_id -> ultimul (ts, sent, recv) cumulativ, pentru calculul ratei
_last_raw: dict[int, tuple[float, int, int]] = {}
_lock = Lock()


def reset() -> None:
    """Goleste tot (folosit in teste)."""
    with _lock:
        _buffers.clear()
        _last_raw.clear()


def record_sample(device_id: int, ts: float, sent: int, recv: int, conn_count: int) -> None:
    """Inregistreaza un sample cumulativ; calculeaza rata (KB/s) fata de
    sample-ul anterior. Primul sample per device e doar baseline (fara rata)."""
    with _lock:
        prev = _last_raw.get(device_id)
        _last_raw[device_id] = (ts, sent, recv)
        if prev is None:
            return  # baseline
        p_ts, p_sent, p_recv = prev
        dt = ts - p_ts
        if dt <= 0:
            return
        sent_rate = max(0, sent - p_sent) / dt / 1024.0
        recv_rate = max(0, recv - p_recv) / dt / 1024.0
        buf = _buffers.setdefault(device_id, deque(maxlen=MAX_SAMPLES))
        buf.append({
            "ts": ts,
            "sent_rate_kbps": round(sent_rate, 2),
            "recv_rate_kbps": round(recv_rate, 2),
            "conn_count": conn_count,
        })


def get_series(device_id: int) -> list[dict]:
    """Seria curenta de sample-uri pentru un device (gol daca nu exista)."""
    with _lock:
        return list(_buffers.get(device_id, []))
