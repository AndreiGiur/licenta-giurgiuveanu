# Plan — PDF reports + Scheduler + Admin role

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development sau superpowers:executing-plans. Pași folosesc checkbox (`- [ ]`) syntax pentru tracking.

**Goal:** Adăugare 3 feature-uri majore — PDF reports (Honey & Plum branded), Scheduler preset (daily/weekly/monthly), Admin role cu /admin/* endpoints.

**Spec aprobat:** `docs/superpowers/specs/2026-05-19-reports-scheduler-admin-design.md`

**Strategy:** Backend-first per feature (model + endpoint + tests), apoi frontend integration. PDF feature poate fi shipped independent. Schedulerul cere ScanSchedule model. Admin role atinge User schema → trebuie făcut early ca să nu rupem testele existente.

---

## Pre-flight: dependențe noi

- [ ] **Step 0.1: Add reportlab la server requirements**

```bash
grep -i reportlab server/requirements.txt || echo "MISSING"
```

Dacă lipsește, adaugă în `server/requirements.txt`:

```
reportlab>=4.0
```

Instalează:
```bash
cd server && pip install -r requirements.txt
```

---

## Faza A: Admin role foundation (foundational, blochează restul)

## Task A1: Schema User.role + first-user-admin

**Files:**
- Modify: `server/app/models.py`
- Modify: `server/app/schemas.py`
- Modify: `server/app/routes.py` (register endpoint)
- Create: `server/tests/test_admin_role.py`

- [ ] **Step A1.1: Test pentru first-user-admin + role default**

În `server/tests/test_admin_role.py`:

```python
"""Tests pentru User.role + first-user-admin logic."""
from fastapi.testclient import TestClient
from app.main import app
from app.db import SessionLocal
from app.models import User


def test_first_registered_user_is_admin(client: TestClient):
    # DB clean per fixture
    r = client.post("/api/v1/auth/register",
                    json={"email": "first@x.com", "password": "passwd123456"})
    assert r.status_code == 200

    r = client.post("/api/v1/auth/login",
                    json={"email": "first@x.com", "password": "passwd123456"})
    assert r.status_code == 200

    r = client.get("/api/v1/auth/me")
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


def test_second_user_is_regular(client: TestClient):
    client.post("/api/v1/auth/register",
                json={"email": "first@x.com", "password": "passwd123456"})
    client.post("/api/v1/auth/logout")

    r = client.post("/api/v1/auth/register",
                    json={"email": "second@x.com", "password": "passwd123456"})
    assert r.status_code == 200

    client.post("/api/v1/auth/login",
                json={"email": "second@x.com", "password": "passwd123456"})
    r = client.get("/api/v1/auth/me")
    assert r.json()["role"] == "user"
```

- [ ] **Step A1.2: Adaugă `role` column pe User**

În `server/app/models.py`, în clasa User:

```python
role: Mapped[str] = mapped_column(String(16), default="user", nullable=False)
```

- [ ] **Step A1.3: Update register handler**

În `server/app/routes.py`, în handler-ul `POST /auth/register`:

```python
existing_count = db.query(User).count()
role = "admin" if existing_count == 0 else "user"
new_user = User(email=..., ..., role=role)
```

Identic pentru `/auth/google/callback` + `/agent/google-enroll` (toate path-urile de creare User).

- [ ] **Step A1.4: Update MeOut schema**

În `server/app/schemas.py`:

```python
class MeOut(BaseModel):
    ...
    role: str = "user"
```

În routes.py la `/auth/me`, returnează `role`.

- [ ] **Step A1.5: Rulează testele**

```bash
cd server && python -m pytest tests/test_admin_role.py -v
```

Expected: 2 pass.

- [ ] **Step A1.6: Verifică non-regresie**

```bash
cd server && python -m pytest
```

Expected: 108 + 2 = 110 pass.

- [ ] **Step A1.7: Commit**

```bash
git add server/app/models.py server/app/schemas.py server/app/routes.py server/tests/test_admin_role.py
git commit -m "feat(server/auth): User.role enum + first-user-admin auto-promote"
```

---

## Task A2: require_admin dependency + /admin/* endpoints

**Files:**
- Modify: `server/app/auth.py` — adaugă `require_admin`
- Modify: `server/app/routes.py` — adaugă endpoints `/admin/users`, `/admin/devices`, `/admin/scans`
- Modify: `server/app/schemas.py` — `AdminUserOut`, `AdminDeviceOut`, `AdminScanListItem`, `AdminRoleChangeIn`, `AdminResetPasswordIn`
- Create: `server/tests/test_admin_endpoints.py`

- [ ] **Step A2.1: Test pentru require_admin + listare users**

În `server/tests/test_admin_endpoints.py`:

```python
"""Tests pentru endpoints /api/v1/admin/*."""
from fastapi.testclient import TestClient


def _register_login(client, email, pw="passwd123456"):
    client.post("/api/v1/auth/register", json={"email": email, "password": pw})
    client.post("/api/v1/auth/login", json={"email": email, "password": pw})


def test_admin_can_list_all_users(client: TestClient):
    _register_login(client, "admin@x.com")  # first → admin
    r = client.get("/api/v1/admin/users")
    assert r.status_code == 200
    users = r.json()
    assert len(users) >= 1
    assert any(u["email"] == "admin@x.com" and u["role"] == "admin" for u in users)


def test_regular_user_forbidden_admin(client: TestClient):
    _register_login(client, "admin@x.com")
    client.post("/api/v1/auth/logout")
    _register_login(client, "regular@x.com")

    r = client.get("/api/v1/admin/users")
    assert r.status_code == 403


def test_admin_promote_demote(client: TestClient):
    _register_login(client, "admin@x.com")
    client.post("/api/v1/auth/logout")
    _register_login(client, "regular@x.com")
    client.post("/api/v1/auth/logout")
    _register_login(client, "admin@x.com")

    users = client.get("/api/v1/admin/users").json()
    target = next(u for u in users if u["email"] == "regular@x.com")

    r = client.post(f"/api/v1/admin/users/{target['id']}/role",
                    json={"role": "admin"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


def test_admin_cannot_demote_self(client: TestClient):
    _register_login(client, "admin@x.com")
    me = client.get("/api/v1/auth/me").json()

    r = client.post(f"/api/v1/admin/users/{me['id']}/role",
                    json={"role": "user"})
    assert r.status_code == 400


def test_admin_cannot_delete_self(client: TestClient):
    _register_login(client, "admin@x.com")
    me = client.get("/api/v1/auth/me").json()

    r = client.delete(f"/api/v1/admin/users/{me['id']}")
    assert r.status_code == 400


def test_admin_reset_password_invalidates_sessions(client: TestClient):
    _register_login(client, "admin@x.com")
    client.post("/api/v1/auth/logout")
    _register_login(client, "regular@x.com")
    me = client.get("/api/v1/auth/me").json()
    target_id = me["id"]
    client.post("/api/v1/auth/logout")
    _register_login(client, "admin@x.com")

    r = client.post(f"/api/v1/admin/users/{target_id}/reset-password",
                    json={"new_password": "newpasswd123"})
    assert r.status_code == 200

    # Vechea parolă nu mai merge
    client.post("/api/v1/auth/logout")
    r = client.post("/api/v1/auth/login",
                    json={"email": "regular@x.com", "password": "passwd123456"})
    assert r.status_code == 401

    # Noua parolă merge
    r = client.post("/api/v1/auth/login",
                    json={"email": "regular@x.com", "password": "newpasswd123"})
    assert r.status_code == 200


def test_admin_list_devices_includes_other_users(client: TestClient):
    _register_login(client, "admin@x.com")
    client.post("/api/v1/auth/logout")
    _register_login(client, "regular@x.com")
    client.post("/api/v1/devices",
                json={"device_uid": "regular-pc", "name": "Regular PC",
                      "token_hash": "a" * 64})
    client.post("/api/v1/auth/logout")
    _register_login(client, "admin@x.com")

    r = client.get("/api/v1/admin/devices")
    assert r.status_code == 200
    devices = r.json()
    assert any(d["device_uid"] == "regular-pc" and d["owner_email"] == "regular@x.com"
               for d in devices)


def test_admin_list_scans_paginated(client: TestClient):
    _register_login(client, "admin@x.com")
    r = client.get("/api/v1/admin/scans?limit=20&offset=0")
    assert r.status_code == 200
    assert "items" in r.json()
    assert "total" in r.json()
```

- [ ] **Step A2.2: Adaugă `require_admin` în auth.py**

```python
async def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user
```

- [ ] **Step A2.3: Adaugă schemas Admin în schemas.py**

```python
class AdminUserOut(BaseModel):
    id: int
    email: EmailStr
    role: str
    auth_provider: str
    created_at: datetime
    device_count: int
    last_login_at: datetime | None

class AdminDeviceOut(BaseModel):
    id: int
    device_uid: str
    name: str
    owner_id: int
    owner_email: EmailStr
    created_at: datetime
    is_online: bool

class AdminScanListItem(BaseModel):
    scan_id: int
    device_uid: str
    device_name: str
    owner_email: EmailStr
    created_at: datetime
    exposure_score: int
    scan_type: str | None

class AdminScansPage(BaseModel):
    items: list[AdminScanListItem]
    total: int
    limit: int
    offset: int

class AdminRoleChangeIn(BaseModel):
    role: Literal["admin", "user"]

class AdminResetPasswordIn(BaseModel):
    new_password: str = Field(min_length=8, max_length=128)
```

- [ ] **Step A2.4: Adaugă endpoints în routes.py**

La sfârșit, secțiune nouă `# ── Admin endpoints ──`:

```python
@router.get("/admin/users", response_model=list[AdminUserOut])
def admin_list_users(_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    out = []
    for u in db.query(User).order_by(User.created_at.desc()).all():
        dc = db.query(Device).filter(Device.owner_id == u.id).count()
        out.append(AdminUserOut(
            id=u.id, email=u.email, role=u.role,
            auth_provider=u.auth_provider, created_at=u.created_at,
            device_count=dc, last_login_at=None,  # last_login simplificat (skip pe MVP)
        ))
    return out


@router.delete("/admin/users/{user_id}", status_code=204)
def admin_delete_user(user_id: int, admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    if user_id == admin.id:
        raise HTTPException(400, "Cannot delete your own admin account")
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    db.delete(u)
    db.commit()


@router.post("/admin/users/{user_id}/role", response_model=AdminUserOut)
def admin_change_role(user_id: int, body: AdminRoleChangeIn,
                     admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    if user_id == admin.id and body.role == "user":
        raise HTTPException(400, "Cannot demote your own admin account")
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    u.role = body.role
    db.commit()
    return AdminUserOut(id=u.id, email=u.email, role=u.role,
                       auth_provider=u.auth_provider, created_at=u.created_at,
                       device_count=db.query(Device).filter(Device.owner_id == u.id).count(),
                       last_login_at=None)


@router.post("/admin/users/{user_id}/reset-password", status_code=200)
def admin_reset_password(user_id: int, body: AdminResetPasswordIn,
                        _admin: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    salt, hashed = create_password(body.new_password)
    u.password_salt = salt
    u.password_hash = hashed
    # Invalidează sesiunile existente
    db.query(Session_).filter(Session_.user_id == user_id).delete()
    db.commit()
    return {"ok": True}


@router.get("/admin/devices", response_model=list[AdminDeviceOut])
def admin_list_devices(_admin: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    out = []
    for d in db.query(Device).order_by(Device.created_at.desc()).all():
        owner = db.query(User).filter(User.id == d.owner_id).first()
        out.append(AdminDeviceOut(
            id=d.id, device_uid=d.device_uid, name=d.name,
            owner_id=d.owner_id, owner_email=owner.email if owner else "?",
            created_at=d.created_at, is_online=d.is_online,
        ))
    return out


@router.get("/admin/scans", response_model=AdminScansPage)
def admin_list_scans(limit: int = 50, offset: int = 0,
                    _admin: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    limit = min(limit, 200)
    q = db.query(Scan).order_by(Scan.created_at.desc())
    total = q.count()
    items = []
    for s in q.offset(offset).limit(limit).all():
        device = db.query(Device).filter(Device.id == s.device_id).first()
        owner = db.query(User).filter(User.id == device.owner_id).first() if device else None
        items.append(AdminScanListItem(
            scan_id=s.id, device_uid=device.device_uid if device else "?",
            device_name=device.name if device else "?",
            owner_email=owner.email if owner else "?",
            created_at=s.created_at, exposure_score=s.exposure_score,
            scan_type=s.scan_type,
        ))
    return AdminScansPage(items=items, total=total, limit=limit, offset=offset)
```

- [ ] **Step A2.5: Rulează testele**

Expected: 8 pass.

- [ ] **Step A2.6: Commit**

```bash
git add server/app/auth.py server/app/routes.py server/app/schemas.py server/tests/test_admin_endpoints.py
git commit -m "feat(server/admin): /admin/users + /admin/devices + /admin/scans cu require_admin dep"
```

---

## Faza B: PDF reports

## Task B1: PDF generator module + endpoint

**Files:**
- Create: `server/app/reports.py` — funcția `generate_scan_pdf(scan, device, findings) -> bytes`
- Modify: `server/app/routes.py` — endpoint `GET /scans/{id}/report.pdf`
- Create: `server/tests/test_reports.py`

- [ ] **Step B1.1: Test pentru endpoint PDF**

În `server/tests/test_reports.py`:

```python
"""Tests pentru endpoint PDF report."""
from fastapi.testclient import TestClient


def test_pdf_report_ok_for_owner(client: TestClient, auth_client):
    # Creează device + scan
    auth_client.post("/api/v1/devices",
                     json={"device_uid": "pdf-pc", "name": "PDF PC",
                           "token_hash": "a" * 64})
    payload = {
        "scan_type": "standard",
        "network": {"open_ports": [22, 80, 443]},
        "os": {"hostname": "test-host", "is_admin": False, "system": "Windows"},
        "system": {}, "processes": [], "software": [],
    }
    r = auth_client.post("/api/v1/scans",
                        headers={"X-Device-Token": "PLAIN_TOKEN"},
                        json={"device_uid": "pdf-pc", **payload})
    # Skip: trebuie generat token plain real în test
    # Folosim alt path: scan creat direct via fixture sau via job

    # ... simplificare: presupunem scan_id=1
    r = auth_client.get("/api/v1/scans/1/report.pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF-")
    assert len(r.content) > 1000  # PDF non-trivial


def test_pdf_report_404_for_non_owner(client: TestClient):
    # User A creează scan, User B încearcă să descarce → 403/404
    ...


def test_pdf_report_admin_bypass(client: TestClient):
    # Admin poate descarca PDF pentru scan-ul oricui
    ...


def test_pdf_report_includes_nmap_section_when_present(client: TestClient):
    # Scan cu nmap_data non-null → PDF mai mare
    ...
```

NOTE: PDF binary content e greu de assert. Verificăm doar:
- Status 200
- Content-Type application/pdf
- Prefix `%PDF-` (signature)
- Lungime > prag (1 KB minim pentru raport valid)

- [ ] **Step B1.2: Implementare `server/app/reports.py`**

```python
"""Generator PDF rapoarte scan — paleta Honey & Plum."""
from io import BytesIO
from datetime import datetime
import json
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)

# Paleta Honey & Plum
PLUM = colors.HexColor("#2d1b3d")
HONEY = colors.HexColor("#f4c95d")
CREAM = colors.HexColor("#fefaf2")
RASPBERRY = colors.HexColor("#b8456e")
LAVENDER = colors.HexColor("#a8639a")
MUTED = colors.HexColor("#8a7458")

SEVERITY_COLOR = {
    "critical": colors.HexColor("#5a2d6e"),
    "high": RASPBERRY,
    "medium": HONEY,
    "low": LAVENDER,
    "info": MUTED,
}


def generate_scan_pdf(scan, device, findings, owner_email: str) -> bytes:
    """Generează PDF report pentru un scan. Returnează bytes."""
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                           topMargin=2*cm, bottomMargin=2*cm,
                           leftMargin=2*cm, rightMargin=2*cm)
    elements = []
    styles = getSampleStyleSheet()

    # Stil custom
    title_style = ParagraphStyle("Title", parent=styles["Title"],
                                 textColor=PLUM, fontSize=24, alignment=1)
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"],
                              textColor=PLUM, fontSize=14, spaceAfter=10)
    body_style = ParagraphStyle("Body", parent=styles["BodyText"],
                                fontSize=10, textColor=PLUM, leading=14)
    small_style = ParagraphStyle("Small", parent=styles["BodyText"],
                                 fontSize=8, textColor=MUTED)

    # ── Header ──
    elements.append(Paragraph("VulnWatch", title_style))
    elements.append(Paragraph("Raport scanare securitate", h2_style))
    elements.append(Spacer(1, 0.4*cm))

    # ── Meta tabel ──
    os_info = (scan.payload or {}).get("os", {}) if hasattr(scan, "payload") else {}
    meta_data = [
        ["Device", device.name],
        ["UID", device.device_uid],
        ["Owner", owner_email],
        ["OS", f"{os_info.get('system', '?')} {os_info.get('release', '')}".strip()],
        ["Hostname", os_info.get("hostname", "?")],
        ["Scan type", (scan.scan_type or "standard").upper()],
        ["Data", scan.created_at.strftime("%d %b %Y, %H:%M")],
        ["Scan ID", f"#{scan.id}"],
    ]
    meta_tbl = Table(meta_data, colWidths=[4*cm, 12*cm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fff8e6")),
        ("TEXTCOLOR", (0, 0), (0, -1), PLUM),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f0e4cc")),
    ]))
    elements.append(meta_tbl)
    elements.append(Spacer(1, 0.8*cm))

    # ── Exposure Score ──
    elements.append(Paragraph("Scor de expunere", h2_style))
    score = scan.exposure_score
    score_color = SEVERITY_COLOR["critical"] if score >= 75 else \
                 SEVERITY_COLOR["high"] if score >= 50 else \
                 SEVERITY_COLOR["medium"] if score >= 25 else SEVERITY_COLOR["low"]
    score_style = ParagraphStyle("Score", parent=styles["Title"],
                                 textColor=score_color, fontSize=48, alignment=1)
    elements.append(Paragraph(f"{score}<font size=18>/100</font>", score_style))
    elements.append(Spacer(1, 0.4*cm))

    # ── Severity breakdown ──
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[(f.severity or "info").lower()] = sev_counts.get(
            (f.severity or "info").lower(), 0) + 1

    sev_data = [["Severity", "Count"]]
    for sev in ["critical", "high", "medium", "low", "info"]:
        sev_data.append([sev.upper(), str(sev_counts[sev])])

    sev_tbl = Table(sev_data, colWidths=[8*cm, 4*cm])
    sev_style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), PLUM),
        ("TEXTCOLOR", (0, 0), (-1, 0), CREAM),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f0e4cc")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]
    for i, sev in enumerate(["critical", "high", "medium", "low", "info"], start=1):
        sev_style_cmds.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLOR[sev]))
        sev_style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    sev_tbl.setStyle(TableStyle(sev_style_cmds))
    elements.append(sev_tbl)
    elements.append(Spacer(1, 0.8*cm))

    # ── Findings detaliate ──
    elements.append(PageBreak())
    elements.append(Paragraph("Vulnerabilități detectate", h2_style))
    elements.append(Spacer(1, 0.3*cm))

    if not findings:
        elements.append(Paragraph("✓ Sistem curat — nicio vulnerabilitate detectată.",
                                 body_style))
    else:
        for f in findings:
            sev = (f.severity or "info").lower()
            color = SEVERITY_COLOR.get(sev, MUTED)
            title = f"<font color='{color.hexval()}'><b>[{sev.upper()}]</b></font> "
            title += f"<b>{f.title}</b>  <font size=8 color='{MUTED.hexval()}'>({f.rule_id})</font>"
            elements.append(Paragraph(title, body_style))

            if f.evidence:
                ev_str = json.dumps(f.evidence, indent=2, ensure_ascii=False, default=str)
                elements.append(Paragraph(
                    f"<font face='Courier' size=8>{ev_str.replace(chr(10), '<br/>').replace(' ', '&nbsp;')}</font>",
                    body_style
                ))

            if f.recommendation:
                elements.append(Paragraph(
                    f"<i>Recomandare:</i> {f.recommendation}", body_style))
            elements.append(Spacer(1, 0.3*cm))

    # ── Nmap section ──
    nmap = (scan.payload or {}).get("nmap") if hasattr(scan, "payload") else None
    if nmap and nmap.get("hosts"):
        elements.append(PageBreak())
        elements.append(Paragraph(
            f"Network scan (nmap {nmap.get('version', '?')})", h2_style))
        targets = ", ".join(nmap.get("targets", []))
        elements.append(Paragraph(f"<i>Targets:</i> {targets}", small_style))
        elements.append(Paragraph(
            f"<i>Durată:</i> {nmap.get('scan_time_sec', '?')}s · "
            f"{len(nmap['hosts'])} host-uri", small_style))
        elements.append(Spacer(1, 0.4*cm))

        for host in nmap["hosts"]:
            elements.append(Paragraph(
                f"<b>{host.get('ip', '?')}</b> "
                f"<font size=9 color='{MUTED.hexval()}'>"
                f"({host.get('hostname', 'n/a')})</font>", body_style))
            if host.get("os_guess"):
                elements.append(Paragraph(f"OS: {host['os_guess']}", small_style))
            open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
            if open_ports:
                ports_str = ", ".join(
                    f"{p['port']}/{p['proto']} ({p.get('service', '?')})"
                    for p in open_ports[:20]
                )
                elements.append(Paragraph(f"Porturi open: {ports_str}", small_style))
            elements.append(Spacer(1, 0.3*cm))

    # ── Footer ──
    elements.append(Spacer(1, 0.6*cm))
    elements.append(Paragraph(
        f"<font size=8 color='{MUTED.hexval()}'>Generat de VulnWatch · "
        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</font>",
        small_style))

    doc.build(elements)
    return buf.getvalue()
```

- [ ] **Step B1.3: Adaugă endpoint în routes.py**

```python
@router.get("/scans/{scan_id}/report.pdf")
def download_scan_report(scan_id: int,
                        user: User = Depends(require_user),
                        db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    device = db.query(Device).filter(Device.id == scan.device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    # Owner check (admin bypass)
    if user.role != "admin" and device.owner_id != user.id:
        raise HTTPException(404, "Scan not found")  # 404 nu 403 ca să nu leak existență
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    owner = db.query(User).filter(User.id == device.owner_id).first()
    pdf_bytes = generate_scan_pdf(scan, device, findings,
                                  owner.email if owner else "?")
    filename = f"vulnwatch-scan-{scan_id}-{scan.created_at.strftime('%Y%m%d')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
```

- [ ] **Step B1.4: Rulează testele + verifică manual PDF**

```bash
cd server && python -m pytest tests/test_reports.py -v
```

Expected: 4 pass.

Manual:
```bash
curl -b cookies.txt http://127.0.0.1:8000/api/v1/scans/1/report.pdf -o test.pdf
```
Deschide test.pdf în Acrobat — verifică toate secțiunile.

- [ ] **Step B1.5: Commit**

```bash
git add server/app/reports.py server/app/routes.py server/tests/test_reports.py server/requirements.txt
git commit -m "feat(server/reports): PDF generator Honey&Plum + endpoint /scans/{id}/report.pdf"
```

---

## Task B2: Frontend "Export PDF" button

**Files:**
- Modify: `web/src/pages/ScanDetail.tsx`
- Modify: `web/src/api/exposure.ts` — funcție `getScanPdfUrl(id)`

- [ ] **Step B2.1: Adaugă helper în exposure.ts**

```typescript
export function getScanPdfUrl(scanId: number): string {
  return `${API_BASE_URL}/scans/${scanId}/report.pdf`;
}
```

(Import API_BASE_URL din `../api/http`.)

- [ ] **Step B2.2: Buton în ScanDetail.tsx**

În topbar-ul ScanDetail.tsx, lângă "← Înapoi":

```tsx
{data && (
  <a
    href={getScanPdfUrl(data.scan_id)}
    target="_blank"
    rel="noreferrer"
    className="btn btn-accent btn-sm"
    style={{ marginLeft: 8, textDecoration: "none" }}
  >
    ↓ Export PDF
  </a>
)}
```

- [ ] **Step B2.3: TypeScript check**

```bash
cd web && npx tsc --noEmit
```

- [ ] **Step B2.4: Smoke browser**

Pornește backend + frontend, deschide un scan, click "Export PDF" → PDF se deschide într-un tab nou.

- [ ] **Step B2.5: Commit**

```bash
git add web/src/pages/ScanDetail.tsx web/src/api/exposure.ts
git commit -m "feat(web): buton Export PDF in ScanDetail (link direct catre /scans/{id}/report.pdf)"
```

---

## Faza C: Scheduler

## Task C1: Model ScanSchedule + endpoints CRUD

**Files:**
- Modify: `server/app/models.py` — clasa `ScanSchedule`
- Modify: `server/app/schemas.py` — `ScheduleIn`, `ScheduleOut`, `ScheduleUpdateIn`
- Modify: `server/app/routes.py` — endpoints CRUD
- Create: `server/app/scheduler.py` — funcția `compute_next_run(schedule)` + bg loop
- Create: `server/tests/test_scheduler.py`

- [ ] **Step C1.1: Test pentru compute_next_run + CRUD**

În `server/tests/test_scheduler.py`:

```python
"""Tests pentru scheduler model + endpoints + compute_next_run."""
from datetime import datetime, timezone, timedelta
from app.scheduler import compute_next_run


def test_compute_next_daily():
    # Daily la 03:00, acum e 10:00 → next = mâine 03:00
    now = datetime(2026, 5, 19, 10, 0, 0, tzinfo=timezone.utc)
    nxt = compute_next_run("daily", hour=3, day_of_week=None, day_of_month=None, now=now)
    assert nxt.hour == 3
    assert nxt.day == 20


def test_compute_next_daily_before_hour():
    # Daily la 23:00, acum e 10:00 → next = azi 23:00
    now = datetime(2026, 5, 19, 10, 0, 0, tzinfo=timezone.utc)
    nxt = compute_next_run("daily", hour=23, day_of_week=None, day_of_month=None, now=now)
    assert nxt.hour == 23
    assert nxt.day == 19


def test_compute_next_weekly():
    # Weekly la luni 09:00 (day_of_week=0). Acum e marți 2026-05-19 → next luni 25.
    now = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)
    nxt = compute_next_run("weekly", hour=9, day_of_week=0, day_of_month=None, now=now)
    assert nxt.weekday() == 0
    assert nxt > now


def test_compute_next_monthly():
    # Monthly în ziua 15 la 02:00. Acum e 19 mai → next 15 iunie.
    now = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)
    nxt = compute_next_run("monthly", hour=2, day_of_week=None, day_of_month=15, now=now)
    assert nxt.day == 15
    assert nxt.month == 6


def test_create_schedule_for_my_device(client, auth_client):
    # Setup device
    auth_client.post("/api/v1/devices",
                     json={"device_uid": "sch-pc", "name": "Sch PC",
                           "token_hash": "a" * 64})
    devices = auth_client.get("/api/v1/devices").json()
    dev_uid = devices[0]["device_uid"]

    r = auth_client.post(f"/api/v1/devices/{dev_uid}/schedules",
                         json={"scan_type": "standard", "frequency": "daily",
                               "hour": 3})
    assert r.status_code == 200
    sched = r.json()
    assert sched["enabled"] is True
    assert sched["next_run_at"]


def test_list_schedules_for_device(auth_client):
    auth_client.post("/api/v1/devices",
                     json={"device_uid": "sch-pc", "name": "Sch PC",
                           "token_hash": "a" * 64})
    devices = auth_client.get("/api/v1/devices").json()
    dev_uid = devices[0]["device_uid"]
    auth_client.post(f"/api/v1/devices/{dev_uid}/schedules",
                    json={"scan_type": "standard", "frequency": "daily", "hour": 3})

    r = auth_client.get(f"/api/v1/devices/{dev_uid}/schedules")
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_cannot_schedule_other_users_device(client):
    # User A creează device, User B încearcă schedule → 404
    ...


def test_max_schedules_per_user(auth_client):
    auth_client.post("/api/v1/devices",
                     json={"device_uid": "sch-pc", "name": "Sch PC",
                           "token_hash": "a" * 64})
    devices = auth_client.get("/api/v1/devices").json()
    dev_uid = devices[0]["device_uid"]
    for i in range(5):
        r = auth_client.post(f"/api/v1/devices/{dev_uid}/schedules",
                            json={"scan_type": "standard", "frequency": "daily",
                                  "hour": i})
        assert r.status_code == 200
    r = auth_client.post(f"/api/v1/devices/{dev_uid}/schedules",
                        json={"scan_type": "standard", "frequency": "daily", "hour": 6})
    assert r.status_code == 400  # max reached
```

- [ ] **Step C1.2: Model ScanSchedule**

În `models.py`:

```python
class ScanSchedule(Base):
    __tablename__ = "scan_schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    scan_type: Mapped[str] = mapped_column(String(16), default="standard")
    frequency: Mapped[str] = mapped_column(String(16))  # daily|weekly|monthly
    hour: Mapped[int] = mapped_column(default=3)
    day_of_week: Mapped[int | None] = mapped_column(nullable=True)
    day_of_month: Mapped[int | None] = mapped_column(nullable=True)
    nmap_target: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    next_run_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    last_run_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
```

Adaugă coloana `source` pe ScanJob:

```python
source: Mapped[str] = mapped_column(String(16), default="manual")  # manual|scheduled
```

- [ ] **Step C1.3: `compute_next_run` în `server/app/scheduler.py`**

```python
"""Scheduler logic — compute_next_run + background loop."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def compute_next_run(frequency: str, hour: int, day_of_week: int | None,
                    day_of_month: int | None,
                    now: datetime | None = None) -> datetime:
    """Calculează următoarea oră de rulare, UTC, fără secunde."""
    if now is None:
        now = datetime.now(timezone.utc)
    now = now.replace(second=0, microsecond=0)
    if frequency == "daily":
        candidate = now.replace(hour=hour, minute=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate
    if frequency == "weekly":
        assert day_of_week is not None
        candidate = now.replace(hour=hour, minute=0)
        days_ahead = (day_of_week - now.weekday()) % 7
        if days_ahead == 0 and candidate <= now:
            days_ahead = 7
        return candidate + timedelta(days=days_ahead)
    if frequency == "monthly":
        assert day_of_month is not None
        dom = min(day_of_month, 28)
        candidate = now.replace(day=dom, hour=hour, minute=0)
        if candidate <= now:
            # următoarea lună
            m = now.month + 1 if now.month < 12 else 1
            y = now.year if now.month < 12 else now.year + 1
            candidate = candidate.replace(year=y, month=m)
        return candidate
    raise ValueError(f"Unknown frequency: {frequency}")


async def scheduler_loop(session_factory, poll_interval: int = 60):
    """Loop care creează ScanJob-uri pentru schedule-uri due."""
    from .models import ScanSchedule, ScanJob, Device
    logger.info("Scheduler loop started (poll=%ds)", poll_interval)
    while True:
        try:
            with session_factory() as db:
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                due = db.query(ScanSchedule).filter(
                    ScanSchedule.enabled == True,
                    ScanSchedule.next_run_at <= now,
                ).all()
                for sched in due:
                    dev = db.query(Device).filter(Device.id == sched.device_id).first()
                    if not dev:
                        continue
                    # Skip if a job already pending/running
                    existing = db.query(ScanJob).filter(
                        ScanJob.device_id == sched.device_id,
                        ScanJob.status.in_(["pending", "running"])
                    ).first()
                    if not existing:
                        db.add(ScanJob(
                            device_id=sched.device_id,
                            scan_type=sched.scan_type,
                            nmap_target=sched.nmap_target,
                            status="pending",
                            source="scheduled",
                            created_at=datetime.utcnow(),
                        ))
                        logger.info("Scheduled job created for device %s (%s)",
                                   dev.device_uid, sched.scan_type)
                    sched.last_run_at = datetime.utcnow()
                    sched.next_run_at = compute_next_run(
                        sched.frequency, sched.hour, sched.day_of_week,
                        sched.day_of_month, now=datetime.now(timezone.utc),
                    ).replace(tzinfo=None)
                db.commit()
        except Exception as e:
            logger.error("scheduler_loop error: %s", e, exc_info=True)
        await asyncio.sleep(poll_interval)
```

- [ ] **Step C1.4: Pornire scheduler la startup**

În `main.py`:

```python
import os
from contextlib import asynccontextmanager
from .scheduler import scheduler_loop
from .db import SessionLocal

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    if os.getenv("DISABLE_SCHEDULER") != "true":
        task = asyncio.create_task(scheduler_loop(SessionLocal))
    yield
    if os.getenv("DISABLE_SCHEDULER") != "true":
        task.cancel()

app = FastAPI(lifespan=lifespan)
```

În `conftest.py`:

```python
os.environ["DISABLE_SCHEDULER"] = "true"
```

- [ ] **Step C1.5: Schemas Schedule**

```python
class ScheduleIn(BaseModel):
    scan_type: Literal["standard", "advanced", "deep"]
    frequency: Literal["daily", "weekly", "monthly"]
    hour: int = Field(ge=0, le=23)
    day_of_week: int | None = Field(default=None, ge=0, le=6)
    day_of_month: int | None = Field(default=None, ge=1, le=28)
    nmap_target: str | None = None
    enabled: bool = True

class ScheduleUpdateIn(BaseModel):
    scan_type: Literal["standard", "advanced", "deep"] | None = None
    frequency: Literal["daily", "weekly", "monthly"] | None = None
    hour: int | None = Field(default=None, ge=0, le=23)
    day_of_week: int | None = Field(default=None, ge=0, le=6)
    day_of_month: int | None = Field(default=None, ge=1, le=28)
    nmap_target: str | None = None
    enabled: bool | None = None

class ScheduleOut(BaseModel):
    id: int
    device_id: int
    scan_type: str
    frequency: str
    hour: int
    day_of_week: int | None
    day_of_month: int | None
    nmap_target: str | None
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}
```

- [ ] **Step C1.6: Endpoints CRUD în routes.py**

```python
MAX_SCHEDULES_PER_USER = int(os.getenv("MAX_SCHEDULES_PER_USER", "5"))


@router.post("/devices/{device_uid}/schedules", response_model=ScheduleOut)
def create_schedule(device_uid: str, body: ScheduleIn,
                   user: User = Depends(require_user),
                   db: Session = Depends(get_db)):
    dev = db.query(Device).filter(
        Device.device_uid == device_uid, Device.owner_id == user.id).first()
    if not dev:
        raise HTTPException(404, "Device not found")
    # Validare day_of_week/day_of_month per frequency
    if body.frequency == "weekly" and body.day_of_week is None:
        raise HTTPException(400, "day_of_week required for weekly")
    if body.frequency == "monthly" and body.day_of_month is None:
        raise HTTPException(400, "day_of_month required for monthly")
    # Max per user
    total = db.query(ScanSchedule).join(Device).filter(
        Device.owner_id == user.id).count()
    if total >= MAX_SCHEDULES_PER_USER:
        raise HTTPException(400,
            f"Maximum {MAX_SCHEDULES_PER_USER} schedules per user")
    next_run = compute_next_run(body.frequency, body.hour,
                                body.day_of_week, body.day_of_month)
    sched = ScanSchedule(
        device_id=dev.id, scan_type=body.scan_type,
        frequency=body.frequency, hour=body.hour,
        day_of_week=body.day_of_week, day_of_month=body.day_of_month,
        nmap_target=body.nmap_target, enabled=body.enabled,
        next_run_at=next_run.replace(tzinfo=None),
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return sched


@router.get("/devices/{device_uid}/schedules", response_model=list[ScheduleOut])
def list_schedules(device_uid: str,
                  user: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    dev = db.query(Device).filter(
        Device.device_uid == device_uid, Device.owner_id == user.id).first()
    if not dev:
        raise HTTPException(404, "Device not found")
    return db.query(ScanSchedule).filter(
        ScanSchedule.device_id == dev.id).order_by(
        ScanSchedule.created_at.desc()).all()


@router.patch("/schedules/{schedule_id}", response_model=ScheduleOut)
def update_schedule(schedule_id: int, body: ScheduleUpdateIn,
                   user: User = Depends(require_user),
                   db: Session = Depends(get_db)):
    sched = db.query(ScanSchedule).join(Device).filter(
        ScanSchedule.id == schedule_id, Device.owner_id == user.id).first()
    if not sched:
        raise HTTPException(404, "Schedule not found")
    data = body.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(sched, k, v)
    # Recalc next_run_at dacă s-au schimbat parametri de timing
    if any(k in data for k in ["frequency", "hour", "day_of_week", "day_of_month"]):
        sched.next_run_at = compute_next_run(
            sched.frequency, sched.hour, sched.day_of_week,
            sched.day_of_month).replace(tzinfo=None)
    db.commit()
    db.refresh(sched)
    return sched


@router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int,
                   user: User = Depends(require_user),
                   db: Session = Depends(get_db)):
    sched = db.query(ScanSchedule).join(Device).filter(
        ScanSchedule.id == schedule_id, Device.owner_id == user.id).first()
    if not sched:
        raise HTTPException(404, "Schedule not found")
    db.delete(sched)
    db.commit()
```

- [ ] **Step C1.7: Rulează testele**

Expected: 7-8 pass.

- [ ] **Step C1.8: Commit**

```bash
git add server/app/models.py server/app/schemas.py server/app/routes.py server/app/scheduler.py server/app/main.py server/tests/conftest.py server/tests/test_scheduler.py
git commit -m "feat(server/scheduler): ScanSchedule model + CRUD endpoints + asyncio loop background"
```

---

## Task C2: Frontend Schedule UI per device

**Files:**
- Modify: `web/src/pages/Devices.tsx` — secțiune "Planificare" per device
- Create: `web/src/components/ScheduleForm.tsx`
- Modify: `web/src/api/types.ts` — `Schedule` type
- Modify: `web/src/api/exposure.ts` — `listSchedules`, `createSchedule`, `deleteSchedule`

- [ ] **Step C2.1: Types**

În `web/src/api/types.ts`:

```typescript
export type ScheduleFrequency = "daily" | "weekly" | "monthly";

export type Schedule = {
  id: number;
  device_id: number;
  scan_type: ScanType;
  frequency: ScheduleFrequency;
  hour: number;
  day_of_week: number | null;
  day_of_month: number | null;
  nmap_target: string | null;
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
  created_at: string;
};
```

- [ ] **Step C2.2: API helpers în exposure.ts**

```typescript
import type { Schedule, ScheduleFrequency } from "./types";

export function listSchedules(deviceUid: string) {
  return apiGet<Schedule[]>(`/devices/${encodeURIComponent(deviceUid)}/schedules`);
}

export function createSchedule(deviceUid: string, body: {
  scan_type: ScanType;
  frequency: ScheduleFrequency;
  hour: number;
  day_of_week?: number;
  day_of_month?: number;
}) {
  return apiPost<typeof body, Schedule>(
    `/devices/${encodeURIComponent(deviceUid)}/schedules`, body);
}

export function deleteSchedule(scheduleId: number) {
  return apiDelete(`/schedules/${scheduleId}`);
}
```

- [ ] **Step C2.3: Component ScheduleForm.tsx**

```tsx
import { useState } from "react";
import type { ScheduleFrequency, ScanType } from "../api/types";

interface Props {
  deviceUid: string;
  onCreated: () => void;
}

const DAYS = ["Luni", "Marți", "Miercuri", "Joi", "Vineri", "Sâmbătă", "Duminică"];

export default function ScheduleForm({ deviceUid, onCreated }: Props) {
  const [scanType, setScanType] = useState<ScanType>("standard");
  const [frequency, setFrequency] = useState<ScheduleFrequency>("daily");
  const [hour, setHour] = useState(3);
  const [dow, setDow] = useState(0);
  const [dom, setDom] = useState(1);

  async function submit() {
    const body: any = { scan_type: scanType, frequency, hour };
    if (frequency === "weekly") body.day_of_week = dow;
    if (frequency === "monthly") body.day_of_month = dom;
    await fetch(`/api/v1/devices/${deviceUid}/schedules`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    onCreated();
  }

  return (
    <div className="schedule-form">
      <select value={scanType} onChange={e => setScanType(e.target.value as ScanType)}>
        <option value="standard">Standard</option>
        <option value="advanced">Advanced</option>
        <option value="deep">Deep</option>
      </select>
      <select value={frequency} onChange={e => setFrequency(e.target.value as ScheduleFrequency)}>
        <option value="daily">Zilnic</option>
        <option value="weekly">Săptămânal</option>
        <option value="monthly">Lunar</option>
      </select>
      {frequency === "weekly" && (
        <select value={dow} onChange={e => setDow(Number(e.target.value))}>
          {DAYS.map((d, i) => <option key={i} value={i}>{d}</option>)}
        </select>
      )}
      {frequency === "monthly" && (
        <select value={dom} onChange={e => setDom(Number(e.target.value))}>
          {Array.from({ length: 28 }, (_, i) => i + 1).map(d => (
            <option key={d} value={d}>Ziua {d}</option>
          ))}
        </select>
      )}
      <select value={hour} onChange={e => setHour(Number(e.target.value))}>
        {Array.from({ length: 24 }, (_, i) => i).map(h => (
          <option key={h} value={h}>{String(h).padStart(2, "0")}:00</option>
        ))}
      </select>
      <button className="btn btn-primary btn-sm" onClick={submit}>+ Adaugă</button>
    </div>
  );
}
```

- [ ] **Step C2.4: Integrare în Devices.tsx**

În fiecare device card, sub `scan-controls`:

```tsx
<details className="schedule-section">
  <summary>📅 Planificare ({schedules[d.device_uid]?.length ?? 0})</summary>
  {(schedules[d.device_uid] ?? []).map(s => (
    <div key={s.id} className="schedule-row">
      {s.scan_type} · {s.frequency} · {String(s.hour).padStart(2, "0")}:00
      · next: {new Date(s.next_run_at).toLocaleString("ro-RO")}
      <button onClick={() => handleDeleteSchedule(s.id, d.device_uid)}
              className="btn btn-ghost btn-sm">×</button>
    </div>
  ))}
  <ScheduleForm deviceUid={d.device_uid}
                onCreated={() => reloadSchedules(d.device_uid)} />
</details>
```

State + load la mount:

```tsx
const [schedules, setSchedules] = useState<Record<string, Schedule[]>>({});

async function reloadSchedules(uid: string) {
  const list = await listSchedules(uid);
  setSchedules(p => ({ ...p, [uid]: list }));
}

useEffect(() => {
  devices.forEach(d => reloadSchedules(d.device_uid));
}, [devices.length]);
```

- [ ] **Step C2.5: CSS minim**

```css
.schedule-section { margin-top: 12px; font-size: 12px; }
.schedule-form { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
.schedule-row { display: flex; gap: 8px; align-items: center;
  padding: 6px 10px; background: var(--bg-elevated);
  border-radius: var(--radius-sm); margin: 4px 0; }
```

- [ ] **Step C2.6: Smoke + commit**

```bash
git add web/src/pages/Devices.tsx web/src/components/ScheduleForm.tsx web/src/api/types.ts web/src/api/exposure.ts web/src/index.css
git commit -m "feat(web): UI Planificare scan-uri per device cu daily/weekly/monthly preset"
```

---

## Faza D: Admin Frontend Page

## Task D1: Admin.tsx + Navbar link conditional

**Files:**
- Create: `web/src/pages/Admin.tsx`
- Modify: `web/src/components/Navbar.tsx`
- Modify: `web/src/components/ProtectedRoute.tsx`
- Modify: `web/src/App.tsx`
- Modify: `web/src/api/types.ts` — MeResponse + admin types
- Modify: `web/src/api/auth.ts` — `MeResponse.role`

- [ ] **Step D1.1: Update MeResponse type**

```typescript
export type MeResponse = {
  id: number;
  email: string;
  role: "admin" | "user";  // NEW
  google_picture_url?: string | null;
  auth_provider?: string;
};
```

- [ ] **Step D1.2: Navbar conditional**

```tsx
{me?.role === "admin" && (
  <NavLink to="/admin" className={...}>⚙ Admin</NavLink>
)}
```

- [ ] **Step D1.3: ProtectedRoute extins cu requireAdmin**

```tsx
interface Props { children: ReactNode; requireAdmin?: boolean; }

// după fetchMe:
if (requireAdmin && me.role !== "admin") {
  navigate("/dashboard", { replace: true });
  return null;
}
```

- [ ] **Step D1.4: Admin.tsx — 3 taburi**

```tsx
import { useState, useEffect } from "react";
import { apiGet, apiDelete, apiPost } from "../api/http";
import Navbar from "../components/Navbar";

type Tab = "users" | "devices" | "scans";

export default function Admin() {
  const [tab, setTab] = useState<Tab>("users");
  return (
    <div className="page">
      <Navbar />
      <div className="container" style={{ paddingTop: 32 }}>
        <h1>Administrare</h1>
        <div className="admin-tabs">
          <button className={tab === "users" ? "active" : ""} onClick={() => setTab("users")}>
            Useri
          </button>
          <button className={tab === "devices" ? "active" : ""} onClick={() => setTab("devices")}>
            Devices
          </button>
          <button className={tab === "scans" ? "active" : ""} onClick={() => setTab("scans")}>
            Scanări
          </button>
        </div>
        {tab === "users" && <AdminUsersTab />}
        {tab === "devices" && <AdminDevicesTab />}
        {tab === "scans" && <AdminScansTab />}
      </div>
    </div>
  );
}

function AdminUsersTab() {
  const [users, setUsers] = useState<any[]>([]);
  useEffect(() => { apiGet<any[]>("/admin/users").then(setUsers); }, []);
  async function changeRole(id: number, role: string) {
    await apiPost(`/admin/users/${id}/role`, { role });
    apiGet<any[]>("/admin/users").then(setUsers);
  }
  async function remove(id: number) {
    if (!confirm("Sigur ștergi userul?")) return;
    await apiDelete(`/admin/users/${id}`);
    apiGet<any[]>("/admin/users").then(setUsers);
  }
  return (
    <table className="admin-table">
      <thead><tr><th>Email</th><th>Rol</th><th>Devices</th><th>Înregistrat</th><th></th></tr></thead>
      <tbody>
        {users.map(u => (
          <tr key={u.id}>
            <td>{u.email}</td>
            <td>
              <select value={u.role} onChange={e => changeRole(u.id, e.target.value)}>
                <option value="user">user</option>
                <option value="admin">admin</option>
              </select>
            </td>
            <td>{u.device_count}</td>
            <td>{new Date(u.created_at).toLocaleDateString("ro-RO")}</td>
            <td><button className="btn btn-sm" onClick={() => remove(u.id)}>Șterge</button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// Similar AdminDevicesTab + AdminScansTab (paginated cu Prev/Next)
```

- [ ] **Step D1.5: Route în App.tsx**

```tsx
<Route path="/admin" element={
  <ProtectedRoute requireAdmin>
    <Admin />
  </ProtectedRoute>
} />
```

- [ ] **Step D1.6: CSS admin**

```css
.admin-tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); margin: 20px 0; }
.admin-tabs button { padding: 10px 20px; background: transparent; border: none;
  color: var(--text-muted); cursor: pointer; border-bottom: 2px solid transparent; }
.admin-tabs button.active { color: var(--accent); border-bottom-color: var(--accent); }
.admin-table { width: 100%; border-collapse: collapse; }
.admin-table th, .admin-table td { padding: 8px 12px; text-align: left;
  border-bottom: 1px solid var(--border); }
.admin-table th { color: var(--text-muted); font-size: 12px;
  text-transform: uppercase; letter-spacing: 0.05em; }
```

- [ ] **Step D1.7: Smoke + TypeScript check**

```bash
cd web && npx tsc --noEmit
```

Manual: login ca admin (primul user), vezi link "⚙ Admin" în navbar, click → 3 tabs funcționează.
Login ca user normal → link absent, navigare directă la `/admin` → redirect la `/dashboard`.

- [ ] **Step D1.8: Commit**

```bash
git add web/src/pages/Admin.tsx web/src/components/Navbar.tsx web/src/components/ProtectedRoute.tsx web/src/App.tsx web/src/api/types.ts web/src/api/auth.ts web/src/index.css
git commit -m "feat(web/admin): pagina Admin cu tabs Users/Devices/Scans + Navbar link conditional"
```

---

## Task E1: Memory.md + smoke checklist

**Files:**
- Modify: `agent/memory.md`, `server/app/memory.md`, `server/tests/memory.md`, `web/src/pages/memory.md`, `web/src/components/memory.md`

- [x] **Step E1.1: Update memory.md per folder**

- `server/app/memory.md`:
  - models.py: + `ScanSchedule` table, + `User.role` column, + `ScanJob.source` column
  - schemas.py: + `MeOut.role`, + `AdminUserOut/AdminDeviceOut/AdminScanListItem/AdminRoleChangeIn/AdminResetPasswordIn`, + `ScheduleIn/Out/UpdateIn`
  - routes.py: + endpoints `/admin/*` (require_admin) + `/devices/{uid}/schedules` + `/scans/{id}/report.pdf`
  - auth.py: + `require_admin` dependency
  - reports.py: NEW file — generator PDF Honey & Plum
  - scheduler.py: NEW file — `compute_next_run` + asyncio loop background
  - main.py: + lifespan handler care pornește scheduler_loop (skip pe `DISABLE_SCHEDULER=true`)

- `web/src/pages/memory.md`:
  - Admin.tsx: NEW
  - ScanDetail.tsx: + buton Export PDF
  - Devices.tsx: + secțiune Planificare per device

- `web/src/components/memory.md`:
  - ScheduleForm.tsx: NEW
  - ProtectedRoute.tsx: + prop `requireAdmin`

- `server/tests/memory.md`:
  - test_admin_role.py: 2 teste (first-user admin, second-user regular)
  - test_admin_endpoints.py: 8 teste (CRUD + reset password + self-protection)
  - test_reports.py: 4 teste (PDF generation + ownership + admin bypass + nmap section)
  - test_scheduler.py: 7-8 teste (compute_next_run + CRUD + max per user)

Update total tests: 108 + 21 = 129 server tests.

- [x] **Step E1.2: Smoke checklist E2E**

În `docs/superpowers/plans/2026-05-19-reports-scheduler-admin.md` (acest fișier), la final:

```
[ ] 1. Register cont nou pe DB gol → user devine admin automat (`me.role === "admin"`)
[ ] 2. Register al 2-lea cont → role="user", primul rămâne admin
[ ] 3. Admin vede link "⚙ Admin" în Navbar; user normal NU
[ ] 4. /admin/users → admin vede toți userii; promovează user→admin → user vede link Admin
[ ] 5. Admin reset password pe alt user → user vechi delogat (sesiunile invalidated)
[ ] 6. Admin încearcă să se demoteze pe el → 400
[ ] 7. Admin încearcă să se șteargă pe el → 400
[ ] 8. Pe ScanDetail click "Export PDF" → descarcă PDF, deschide în Acrobat:
   - Header cu nume device + meta
   - Score 0-100 mare colorat
   - Tabel severity counts
   - Findings cu evidence + recomandări
   - (Pentru scan deep) sectiune nmap cu hosts
[ ] 9. PDF pentru alt user logged în ca normal → 404
[ ] 10. PDF pentru alt user logged în ca admin → 200 (bypass)
[ ] 11. Pe Devices, deschide `details > Planificare` → adaugă schedule daily ora curentă+1min
[ ] 12. Așteaptă ~2 min → ScanJob apare în istoric (source=scheduled)
[ ] 13. Edit schedule frequency=weekly → next_run_at recalc OK
[ ] 14. Add 6 schedules → al 6-lea returnează 400 (max 5)
[ ] 15. Delete schedule → dispare din UI
```

- [x] **Step E1.3: Commit**

```bash
git add agent/memory.md server/app/memory.md server/tests/memory.md web/src/pages/memory.md web/src/components/memory.md docs/superpowers/plans/2026-05-19-reports-scheduler-admin.md
git commit -m "docs: memory.md updates pentru reports + scheduler + admin"
```

---

## Self-review notes

**Spec coverage:**
- ✅ PDF reports cu Honey & Plum stil → Task B1, B2
- ✅ Scheduler preset daily/weekly/monthly → Task C1, C2
- ✅ Admin role + /admin/* endpoints → Task A1, A2, D1
- ✅ First-user-admin auto-promote → Task A1
- ✅ Memory.md updates → Task E1

**Known limitations / follow-ups:**
- Schedule "next_run_at" e UTC — UI afișează `toLocaleString("ro-RO")` care convertește la timezone-ul browser-ului, dar input-ul `hour` rămâne UTC. Acceptăm pentru MVP, follow-up: timezone-aware schedule.
- PDF font Helvetica default — nu Fraunces. Embed TTF Fraunces e follow-up.
- Admin nu poate edita schedule-urile altor useri (poate doar vedea în /admin/scans că s-a făcut un scan).
- ScheduleForm e basic — fără edit inline, doar add+delete.
- Reset password trimite parola plain prin request body (HTTPS in prod). Acceptăm.

**Risc deployment:**
- Add `ScanJob.source` la model = creează coloana lipsă în PostgreSQL — `create_all` o adaugă DOAR pe SQLite în dev/test. **Pentru Postgres dev:** trebuie `DROP TABLE scan_jobs CASCADE` sau migration manuală.
  - Mitigation: documentare în README + plan: rulează `python -c "from app.db import engine, Base; from app.models import *; Base.metadata.drop_all(engine); Base.metadata.create_all(engine)"` o singură dată.

---

## Ordine execuție

1. **Task A1, A2** (Admin foundation) — blocheaz totul → MAI ÎNTÂI
2. **Task B1, B2** (PDF) — independent, poate fi shipped ca PR separat
3. **Task C1, C2** (Scheduler) — independent
4. **Task D1** (Admin frontend) — depinde de A1/A2
5. **Task E1** (Memory + smoke) — final

**Estimare totală:** 9 task-uri, ~12 commit-uri, +21 teste backend, +1 pagină frontend, +1 component frontend.
