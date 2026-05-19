# Design — PDF reports + Scheduler preset + Admin role

**Date:** 2026-05-19
**Status:** Approved
**Author:** Andrei Giurgiuveanu

## Context

VulnWatch a ajuns la nivel de feature parity pentru scan-uri (standard/advanced/deep cu nmap+NSE Lua) și UI matur. Următorul pas e maturizare în "platformă reală" pentru licență:
- **Reports**: după fiecare scan, user-ul vrea un raport descărcabil pe care să-l ataseze la documentație/raportare audit.
- **Scheduler**: scanările manuale sunt OK pentru demo, dar productia cere recurență (zilnic/săptămânal/lunar).
- **Admin role**: până acum oricine se înregistrează vede doar device-urile proprii. Pentru licență vrem un nivel de "platformă administrată" — un admin care vede tot și gestionează userii.

## Decizii tehnice

### 1. PDF generator: `reportlab` (NU weasyprint)

**De ce reportlab:**
- Pur Python — fără dependențe native (weasyprint cere GTK/Cairo pe Windows = pain pentru build).
- Control programatic precis pe layout — putem genera ScoreGauge ca SVG embedded.
- Suportat pe FastAPI sync route, nu necesită subprocess.

**Tradeoff:** sintaxa reportlab e mai verboasă decât HTML→PDF, dar pentru un raport cu structură fixă e gestionabil. ~200-300 LOC pentru un raport complet.

**Endpoint:** `GET /api/v1/scans/{id}/report.pdf` — autentificare prin require_user, verificare ownership prin `scan.device.owner_id == user.id` (admin: bypass).

**Stil Honey & Plum:**
- Background pages: cream (#fefaf2)
- Header: plum (#2d1b3d) cu accent honey (#f4c95d)
- Severity colors mapped: critical=plum-rasberry, high=raspberry, medium=honey, low=lavanda, info=muted
- Font: Helvetica (default reportlab) — Fraunces ar necesita embed TTF (50 KB extra), nu merită complexitate pentru licență.

**Conținut PDF** (4 secțiuni, în această ordine):
1. **Header cover page**: logo "VulnWatch" + nume device + IP/hostname + OS + data scan + scan_type + durată
2. **Score + severity breakdown**: Exposure score 0-100 mare (gauge SVG) + tabel count per severity
3. **Findings detaliate**: grupate pe rule_id source (engine/nmap-lua), fiecare cu title, severity badge, evidence (JSON pretty-printed), recommendation
4. **Network scan (nmap)**: doar dacă `scan.nmap_data` există — host cards cu IP, ports, vulnwatch_findings

### 2. Scheduler: asyncio loop + ScanSchedule table

**De ce loop intern, nu APScheduler:**
- APScheduler ar adăuga 1 dep + complexitate (job store config, executor config, etc.).
- Pentru frecvențe preset (daily/weekly/monthly), un loop FastAPI startup-task la 60s e suficient.
- Persistăm în DB ca să supraviețuim restart-uri (next_run_at recalculat la load).

**Schema model:**

```python
class ScanSchedule(Base):
    __tablename__ = "scan_schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    scan_type: Mapped[str] = mapped_column(String(16))  # standard|advanced|deep
    frequency: Mapped[str] = mapped_column(String(16))  # daily|weekly|monthly
    hour: Mapped[int]                                   # 0-23
    day_of_week: Mapped[int | None]                     # 0-6 (only for weekly)
    day_of_month: Mapped[int | None]                    # 1-28 (only for monthly, cap la 28 ca să evităm Feb)
    enabled: Mapped[bool] = mapped_column(default=True)
    next_run_at: Mapped[datetime]
    last_run_at: Mapped[datetime | None]
    created_at: Mapped[datetime]
    nmap_target: Mapped[str | None] = mapped_column(String(64), nullable=True)  # LAN opt-in
```

**Algoritm next_run_at:**
- `daily`: `today at HH:00`, dacă a trecut → mâine
- `weekly`: găsește următoarea apariție a `day_of_week` la `hour:00`
- `monthly`: găsește următoarea apariție a `day_of_month` (28 max) la `hour:00`

Stochăm `next_run_at` ca să nu recalculăm la fiecare tick — la creare/edit recalc, la fire recalc next.

**Background loop:**

```python
# in main.py startup
async def scheduler_loop():
    while True:
        try:
            with SessionLocal() as db:
                due = db.query(ScanSchedule).filter(
                    ScanSchedule.enabled == True,
                    ScanSchedule.next_run_at <= datetime.utcnow(),
                ).all()
                for sched in due:
                    # creează ScanJob doar dacă device-ul nu are deja un job pending/running
                    existing = db.query(ScanJob).filter(...).first()
                    if not existing:
                        db.add(ScanJob(device_id=..., scan_type=..., nmap_target=..., source="scheduled"))
                    sched.last_run_at = datetime.utcnow()
                    sched.next_run_at = compute_next(sched)
                db.commit()
        except Exception as e:
            logger.error("scheduler_loop error: %s", e)
        await asyncio.sleep(60)
```

**Decizie:** nu rulăm scheduler-ul în testele pytest — folosim env var `DISABLE_SCHEDULER=true` în conftest.py.

**Source tracking pe ScanJob:** adăugăm coloană `source` ("manual"|"scheduled") ca UI să poată distinge.

**Limită:** maxim 5 scheduler-e per user pentru a evita abuz (configurable env `MAX_SCHEDULES_PER_USER=5`).

### 3. Admin role: User.role + require_admin + /admin/*

**Schema:**

```python
class User(Base):
    role: Mapped[str] = mapped_column(String(16), default="user")  # "user" | "admin"
```

**First-user-admin logic:**

```python
# in POST /auth/register
existing_count = db.query(User).count()
new_user = User(..., role="admin" if existing_count == 0 else "user")
```

Idempotent: dacă userul e șters și apoi se reînregistrează când DB e gol, devine din nou admin. OK pentru demo.

**FastAPI dependency:**

```python
async def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Admin role required")
    return user
```

**Endpoint-uri admin** (toate sub `/api/v1/admin/*`, require_admin):
- `GET /admin/users` → listă completă User (id, email, role, created_at, device_count, last_login_at)
- `DELETE /admin/users/{id}` → cascade delete user + sessions + devices + scans (NU permite ștergerea propriului cont)
- `POST /admin/users/{id}/role` body `{role: "admin"|"user"}` → schimbă rol
- `POST /admin/users/{id}/reset-password` body `{new_password: "..."}` → setează parolă nouă (PBKDF2) + invalidează toate sesiunile user-ului
- `GET /admin/devices` → toate device-urile din platformă cu owner_email
- `GET /admin/scans` → toate scan-urile (paginat 50/pagină) cu owner_email + device_name

**MeOut schema** extinsă cu `role` ca frontend să afișeze linkul Admin condiționat.

**UI frontend:**
- `Admin.tsx` cu 3 tab-uri: Users, Devices, Scans
- Link "⚙ Admin" în Navbar — vizibil DOAR dacă `me.role === "admin"`
- `ProtectedRoute` extins cu `requireAdmin?: boolean` prop pentru redirect dacă userul nu e admin.

### 4. Onboarding: register deschis + primul=admin

Status quo `/auth/register` nu se atinge. Singura schimbare: la insert, verificăm dacă tabela User e goală → role="admin".

## Out of scope

- ❌ Reports pe email (separare task, necesită SMTP config + queue)
- ❌ Cron expression complet (preset doar)
- ❌ Multi-tenant organizații (single-level admin only)
- ❌ Admin invite-only signup (register rămâne open)
- ❌ Admin pentru schedule-uri ale altor useri (admin vede dar nu editează — privacy/safety)
- ❌ Retry policy pentru scheduled jobs (dacă agent offline la due, urmează ciclul next, nu re-tryăm)
- ❌ Audit log (cine a făcut ce admin action)
- ❌ Rate-limiting pe endpoint-uri admin

## Gaps acceptate

- Scheduler loop ruleaza într-un singur worker FastAPI — dacă scalăm cu uvicorn workers=4, vor face fiecare loop și duplica job-uri. Acceptăm pentru licență (single worker dev).
- PDF report regenerat la fiecare request — nu cache-uim. La scale: putem stoca în `static/reports/{scan_id}.pdf` și răspunde cu redirect.
- `day_of_month=29-31` mapped automat la 28 → user vede în UI doar 1-28. Edge case minor.

## Riscuri

- **Concurrent fire scheduler**: dacă loop e blocat de un fire lung, următorul tick poate găsi același job due. Mitigation: update next_run_at imediat (atomic), apoi insert ScanJob.
- **First-user-admin race**: doi useri creează cont simultan când DB gol → ambii devin admin. Acceptăm (improbabil în demo).
- **Admin promote/demote propriul cont**: blocăm explicit `if target_user.id == current_user.id and role == "user": raise 400`.

## Test plan

- Backend pytest: ~30 teste noi (~10 PDF, ~10 scheduler, ~10 admin)
- Frontend: type-check + manual smoke
- Smoke checklist E2E manual.
