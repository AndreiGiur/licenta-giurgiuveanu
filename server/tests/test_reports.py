"""Tests pentru endpoint PDF report."""
from fastapi.testclient import TestClient

from server.app.main import app


def _enroll(client, headers, uid="rpt-pc", name="Report PC"):
    from conftest import make_token_pair
    plain, h = make_token_pair()
    r = client.post("/api/v1/devices", headers=headers,
                    json={"device_uid": uid, "name": name, "token_hash": h})
    assert r.status_code == 200, r.text
    return plain


def _submit_scan(client, token, uid="rpt-pc", with_nmap=False):
    payload = {
        "device_uid": uid,
        "os": {"system": "Windows", "release": "10", "version": "22H2",
               "machine": "AMD64", "hostname": "test-pc", "is_admin": False},
        "network": {"open_ports": [22, 445]},
        "processes": [{"pid": 1, "name": "init", "memory_mb": 5}],
        "software": [],
    }
    if with_nmap:
        payload["nmap"] = {
            "version": "7.99",
            "scan_time_sec": 12.5,
            "targets": ["127.0.0.1"],
            "lan_opt_in": False,
            "lua_errors": [],
            "hosts": [{
                "ip": "127.0.0.1",
                "hostname": "localhost",
                "state": "up",
                "os_guess": "Windows 10",
                "ports": [{"port": 445, "proto": "tcp", "state": "open",
                          "service": "microsoft-ds", "version": "", "cpe": ""}],
                "vulnwatch_findings": [],
                "topology": {"role": "workstation", "risk_score": 30, "reasons": []},
            }],
        }
    r = client.post("/api/v1/scans", headers={"X-Device-Token": token}, json=payload)
    assert r.status_code == 200, r.text
    return r.json()["scan_id"]


def test_pdf_report_ok_for_owner(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    token = _enroll(c, headers, uid="rpt-owner")
    scan_id = _submit_scan(c, token, uid="rpt-owner")

    r = c.get(f"/api/v1/scans/{scan_id}/report.pdf", headers=headers)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/pdf")
    assert r.content.startswith(b"%PDF-")
    assert len(r.content) > 1000


def test_pdf_report_404_for_non_owner():
    # User A creează scan, User B nu poate descărca
    ca = TestClient(app)
    ca.post("/api/v1/auth/register",
            json={"email": "pdf-a@x.com", "password": "passwd123456"})
    ca.post("/api/v1/auth/login",
            json={"email": "pdf-a@x.com", "password": "passwd123456"})
    token = _enroll(ca, headers=None, uid="rpt-a")  # uses cookie session
    scan_id = _submit_scan(ca, token, uid="rpt-a")

    cb = TestClient(app)
    cb.post("/api/v1/auth/register",
            json={"email": "pdf-b@x.com", "password": "passwd123456"})
    cb.post("/api/v1/auth/login",
            json={"email": "pdf-b@x.com", "password": "passwd123456"})

    r = cb.get(f"/api/v1/scans/{scan_id}/report.pdf")
    assert r.status_code == 404


def test_pdf_report_admin_bypass(fresh_db_client):
    c = fresh_db_client
    # primul user = admin
    c.post("/api/v1/auth/register",
           json={"email": "admin@x.com", "password": "passwd123456"})
    c.post("/api/v1/auth/login",
           json={"email": "admin@x.com", "password": "passwd123456"})
    c.delete("/api/v1/auth/logout")

    # al 2-lea user = regular, creează scan
    c.post("/api/v1/auth/register",
           json={"email": "regular@x.com", "password": "passwd123456"})
    c.post("/api/v1/auth/login",
           json={"email": "regular@x.com", "password": "passwd123456"})
    token = _enroll(c, headers=None, uid="rpt-bypass")
    scan_id = _submit_scan(c, token, uid="rpt-bypass")
    c.delete("/api/v1/auth/logout")

    # Admin se loghează — poate descărca PDF pentru scan-ul user-ului
    c.post("/api/v1/auth/login",
           json={"email": "admin@x.com", "password": "passwd123456"})
    r = c.get(f"/api/v1/scans/{scan_id}/report.pdf")
    assert r.status_code == 200, r.text
    assert r.content.startswith(b"%PDF-")


def test_pdf_report_includes_nmap_section_when_present(auth_client):
    c, headers = auth_client["client"], auth_client["headers"]
    token = _enroll(c, headers, uid="rpt-nmap")
    scan_id_no_nmap = _submit_scan(c, token, uid="rpt-nmap", with_nmap=False)
    scan_id_with_nmap = _submit_scan(c, token, uid="rpt-nmap", with_nmap=True)

    r1 = c.get(f"/api/v1/scans/{scan_id_no_nmap}/report.pdf", headers=headers)
    r2 = c.get(f"/api/v1/scans/{scan_id_with_nmap}/report.pdf", headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 200
    # PDF cu nmap section ar trebui să fie mai mare
    assert len(r2.content) > len(r1.content)
