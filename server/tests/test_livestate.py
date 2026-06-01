"""Teste pentru ring-buffer-ul de trafic live (app/livestate.py) + endpoint."""
from server.app import livestate
from conftest import make_token_pair


def test_record_computes_rate_and_caps_buffer():
    livestate.reset()
    livestate.record_sample(device_id=1, ts=1000.0, sent=0, recv=0, conn_count=2)
    livestate.record_sample(device_id=1, ts=1010.0, sent=10000, recv=20000, conn_count=3)
    series = livestate.get_series(1)
    assert len(series) >= 1
    last = series[-1]
    assert last["conn_count"] == 3
    assert abs(last["sent_rate_kbps"] - (10000 / 10 / 1024)) < 0.01


def test_buffer_capped_at_60():
    livestate.reset()
    for i in range(80):
        livestate.record_sample(device_id=2, ts=float(i), sent=i * 1000, recv=i * 1000, conn_count=1)
    assert len(livestate.get_series(2)) <= 60


def test_series_isolated_per_device():
    livestate.reset()
    livestate.record_sample(device_id=1, ts=1.0, sent=0, recv=0, conn_count=1)
    livestate.record_sample(device_id=2, ts=1.0, sent=0, recv=0, conn_count=9)
    assert livestate.get_series(99) == []


def test_heartbeat_feeds_livestate(auth_client):
    livestate.reset()
    c = auth_client["client"]
    h = auth_client["headers"]
    tok, th = make_token_pair()
    c.post("/api/v1/devices", headers=h,
           json={"device_uid": "hbnet", "name": "H", "token_hash": th})
    dh = {"X-Device-Token": tok}
    base = {"agent_version": "1.0", "capabilities": [], "os_version": "Win11"}
    c.post("/api/v1/agent/heartbeat", headers=dh,
           json={**base, "net_bytes_sent": 0, "net_bytes_recv": 0, "net_conn_count": 1})
    c.post("/api/v1/agent/heartbeat", headers=dh,
           json={**base, "net_bytes_sent": 10240, "net_bytes_recv": 0, "net_conn_count": 2})
    all_series = [s for d in list(livestate._buffers) for s in livestate.get_series(d)]
    assert any(s["conn_count"] == 2 for s in all_series)


def test_net_traffic_endpoint_returns_series_and_isolates(auth_client):
    livestate.reset()
    c = auth_client["client"]
    h = auth_client["headers"]
    tok, th = make_token_pair()
    c.post("/api/v1/devices", headers=h,
           json={"device_uid": "trafdev", "name": "T", "token_hash": th})
    dh = {"X-Device-Token": tok}
    base = {"agent_version": "1.0", "capabilities": [], "os_version": "Win11"}
    c.post("/api/v1/agent/heartbeat", headers=dh,
           json={**base, "net_bytes_sent": 0, "net_bytes_recv": 0, "net_conn_count": 1})
    c.post("/api/v1/agent/heartbeat", headers=dh,
           json={**base, "net_bytes_sent": 10240, "net_bytes_recv": 5120, "net_conn_count": 2})
    r = c.get("/api/v1/devices/trafdev/net-traffic", headers=h)
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and len(data) >= 1
    assert "sent_rate_kbps" in data[-1] and "conn_count" in data[-1]
    r2 = c.get("/api/v1/devices/nope/net-traffic", headers=h)
    assert r2.status_code == 404
