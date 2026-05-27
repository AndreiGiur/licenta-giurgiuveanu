# VulnWatch — arhitectura sistemului

Acest document conține diagramele de referință pentru arhitectura platformei.
Toate sunt scrise în Mermaid și pot fi vizualizate direct pe GitHub sau în
extensia Mermaid Preview pentru VS Code.

## 1. Componente high-level

Trei componente independente comunică exclusiv prin protocolul REST.

```mermaid
graph LR
    subgraph Dispozitiv["Stația utilizatorului (Windows)"]
        Agent["Agent VulnWatch<br/>(PyInstaller .exe)<br/>~3300 LOC"]
        nmap["nmap 7.99 + NSE Lua<br/>(vulnwatch-audit.nse)"]
        Agent -.invocă.-> nmap
    end

    subgraph Server["Backend (FastAPI)"]
        API["API REST<br/>45 endpoint-uri"]
        Rules["Motor reguli<br/>24 reguli x4 categorii"]
        PDF["Generator PDF<br/>(reportlab)"]
        Scheduler["Scheduler asyncio<br/>(planificări recurente)"]
        API -->|invocă| Rules
        API -->|generează| PDF
        Scheduler -->|creează joburi| API
    end

    subgraph Storage["Persistență"]
        DB[("PostgreSQL 16<br/>(Docker)<br/>7 tabele")]
    end

    subgraph Frontend["Interfață Web"]
        UI["React 19 + TypeScript<br/>(Vite)<br/>7 pagini + componente"]
    end

    User((Utilizator))

    Agent -->|HTTPS<br/>X-Device-Token| API
    UI -->|HTTPS<br/>Cookie HttpOnly| API
    User -->|browser| UI
    API <-->|SQLAlchemy 2.0| DB

    style Agent fill:#fef0d8,stroke:#2d1b3d,stroke-width:2px
    style API fill:#fff3bf,stroke:#2d1b3d,stroke-width:2px
    style UI fill:#e8d5e8,stroke:#2d1b3d,stroke-width:2px
    style DB fill:#d8e5cc,stroke:#2d1b3d,stroke-width:2px
```

**Caracteristici cheie**:
- Agentul nu expune niciun port deschis. Toate conexiunile sunt agent-initiated outbound HTTPS.
- Cele două căi de autentificare (cookie pentru browser, header pentru agent) sunt complet izolate.
- PostgreSQL ascultă exclusiv pe loopback. Accesul extern este blocat la nivel rețea.

---

## 2. Fluxul scan-on-demand

Modelul "pull" prin coadă de joburi. UI cere → Backend creează job → Agent îl preia atomic.

```mermaid
sequenceDiagram
    actor U as Utilizator
    participant UI as Frontend (React)
    participant BE as Backend (FastAPI)
    participant DB as PostgreSQL
    participant A as Agent (Windows)

    Note over A,BE: Agent pollează la 3s + heartbeat la 10s

    U->>UI: Click "Scaneaza Deep"
    UI->>BE: POST /devices/{uid}/scan-jobs
    BE->>DB: INSERT ScanJob (status=pending)
    BE-->>UI: ScanJob {id, status=pending}
    UI->>UI: Polling /scan-jobs/{id} la 2s

    A->>BE: GET /agent/jobs/next
    Note over BE,DB: SELECT FOR UPDATE SKIP LOCKED<br/>(atomic, doi agenti nu preiau acelasi job)
    BE-->>A: Job {id, scan_type, nmap_target?}

    A->>A: Colectează date sistem<br/>(porturi, procese, registry, ...)
    A->>BE: POST /agent/jobs/{id}/progress {30%, "Sistem & OS"}
    BE-->>UI: status=running, progress=30

    alt Scan type = deep
        A->>A: Rulează nmap + NSE Lua
        A->>BE: POST /agent/jobs/{id}/progress {80%, "Nmap"}
    end

    A->>BE: POST /agent/jobs/{id}/result {payload + nmap?}
    BE->>BE: Pydantic validation
    BE->>BE: evaluate(scan) → (score, breakdown, findings)
    BE->>DB: INSERT Scan + Finding[*]
    BE->>DB: UPDATE ScanJob (status=done, scan_id=N)
    BE-->>A: ScanJobOut

    UI->>BE: GET /scan-jobs/{id}
    BE-->>UI: status=done, scan_id=N
    UI->>BE: GET /scans/N
    BE-->>UI: Detalii complete + breakdown + findings
    UI->>U: Afișează rezultatele
```

---

## 3. Motor de scoring multidimensional

Scorul final este o agregare ponderată pe 4 categorii ortogonale.

```mermaid
flowchart LR
    Input([Scan dict]) --> Filter{Filter rules<br/>by scan_type}

    Filter -->|standard ≥0| R1[NET-OPEN-PORTS-1<br/>NET-MANY-PORTS-2<br/>OS-ADMIN-1<br/>PROC-SUSPICIOUS-1<br/>PROC-POWERSHELL-2<br/>SW-VULNERABLE-1<br/>OS-EOL-1<br/>FW-DISABLED-1<br/>USER-ADMIN-1]
    Filter -->|advanced ≥1| R2[+ STARTUP-SUSPICIOUS-1<br/>+ TASK-SUSPICIOUS-1<br/>+ SVC-SUSPICIOUS-1<br/>+ NET-SHARE-1<br/>+ PS-POLICY-1<br/>+ NET-ESTABLISHED-1]
    Filter -->|deep ≥2| R3[+ REG-HIJACK-1<br/>+ WMI-PERSIST-1<br/>+ CERT-UNTRUSTED-1<br/>+ AV-DISABLED-1<br/>+ EVENTLOG-BRUTEFORCE-1<br/>+ EVENTLOG-PRIVESC-1<br/>+ HOSTS-TAMPERED-1<br/>+ BITLOCKER-OFF-1<br/>+ NMAP-LUA-1]

    R1 --> Findings[List finding-uri<br/>cu category +<br/>rule_weight +<br/>confidence +<br/>compliance refs]
    R2 --> Findings
    R3 --> Findings

    Findings --> CR[critical_risk<br/>min 100, Σ sev × w × c]
    Findings --> NE[network_exposure<br/>min 100, Σ sev × w × c]
    Findings --> HG[hygiene<br/>min 100, Σ sev × w × c]
    Findings --> AC[activity<br/>min 100, Σ sev × w × c]

    CR -->|×0.40| Score
    NE -->|×0.30| Score
    HG -->|×0.20| Score
    AC -->|×0.10| Score

    Score([Exposure Score<br/>0–100])

    style Score fill:#f4c95d,stroke:#2d1b3d,stroke-width:3px,color:#2d1b3d
```

**Formula completă**:

```
sev_weight = {critical: 40, high: 20, medium: 10, low: 3, info: 0}

cat_raw[cat] = Σ sev_weight[f.severity] × f.rule_weight × f.rule_confidence
                for all findings f in category `cat`

breakdown[cat] = min(100, round(cat_raw[cat]))

exposure_score = round(
    0.40 × breakdown.critical_risk +
    0.30 × breakdown.network_exposure +
    0.20 × breakdown.hygiene +
    0.10 × breakdown.activity
)
```

---

## 4. Modelul de date

Șapte tabele cu relații cascadabile (ON DELETE CASCADE).

```mermaid
erDiagram
    User ||--o{ Session : "1:N"
    User ||--o{ Device : "1:N"
    User ||--o{ ScanSchedule : "1:N"
    Device ||--o{ Scan : "1:N"
    Device ||--o{ ScanJob : "1:N"
    Device ||--o{ ScanSchedule : "1:N"
    Scan ||--o{ Finding : "1:N"
    ScanJob }o--|| Scan : "creează (opțional)"

    User {
        int id PK
        string email UK
        string password_salt
        string password_hash
        string google_sub
        string auth_provider
        string role "user|admin"
        string first_name
        string last_name
        string default_scan_type
        datetime created_at
    }

    Session {
        int id PK
        int user_id FK
        string token "48 octeți"
        datetime expires_at
        string ip
        string user_agent
    }

    Device {
        int id PK
        int owner_id FK
        string device_uid
        string name
        string device_token_hash "SHA-256"
        datetime last_heartbeat
        json capabilities
        bool nmap_installed
        string local_subnet
    }

    Scan {
        int id PK
        int device_id FK
        int exposure_score
        json score_breakdown "4 categorii"
        json payload "date colectate"
        datetime created_at
    }

    Finding {
        int id PK
        int scan_id FK
        string rule_id
        string title
        string severity
        json evidence
        string recommendation
    }

    ScanJob {
        int id PK
        int device_id FK
        string status "pending|running|done|failed|cancelled"
        string scan_type
        int progress
        string phase
        string nmap_target
        string source "manual|scheduled"
    }

    ScanSchedule {
        int id PK
        int owner_id FK
        int device_id FK
        string frequency "daily|weekly|monthly"
        int hour
        int day_of_week
        int day_of_month
        bool enabled
        datetime next_run_at
        datetime last_run_at
    }
```

---

## 5. Stratul de autentificare

Două sisteme de autentificare separate — pentru browser (cookie HttpOnly) și pentru
agent (token client-generated cu hash pe server).

```mermaid
flowchart TB
    subgraph Browser["Autentificare browser"]
        B_Login[/auth/login/]
        B_Cookie["Cookie HttpOnly<br/>vw_session<br/>SameSite=Lax<br/>Secure (prod)"]
        B_Login --> B_Cookie
        B_Cookie -->|trimis automat<br/>la fiecare request| BE_RU{{require_user}}
    end

    subgraph Agent["Autentificare agent (client-side token)"]
        A_Gen["secrets.token_urlsafe48<br/>generat în executabil"]
        A_Hash["SHA-256 → hash"]
        A_Enroll[/agent/google-enroll<br/>sau POST /devices/]
        A_Plain["Token plain<br/>salvat în config.ini<br/>(local, masina user)"]

        A_Gen --> A_Plain
        A_Gen --> A_Hash
        A_Hash --> A_Enroll
        A_Enroll -->|stocat doar hash| DB1[(device_token_hash)]
        A_Plain -->|X-Device-Token<br/>la fiecare request| BE_DT{{verificare:<br/>SHA-256 plain == hash}}
    end

    subgraph Google["Google OAuth"]
        G_Web[/auth/google/url + callback/]
        G_Desktop[Loopback Redirect<br/>RFC 8252 + PKCE]
        G_Web -->|web flow| BE_Login
        G_Desktop -->|desktop flow| A_Enroll
    end

    BE_Login[/auth/login/] --> BE_DB[(Session table)]
    BE_RU --> BE_DB
    BE_DT --> DB1

    style A_Plain fill:#fef0d8,stroke:#b8456e,stroke-width:2px
    style DB1 fill:#d8e5cc,stroke:#2d1b3d,stroke-width:2px
    style B_Cookie fill:#fef0d8,stroke:#5a2d6e,stroke-width:2px
```

**Observații de securitate**:
- Tokenul de dispozitiv nu părăsește niciodată mașina utilizatorului în formă plain. Compromiterea bazei de date NU oferă acces la dispozitive.
- Cookie-ul de sesiune e HttpOnly — JavaScript nu poate citi tokenul, blocând XSS asupra credențialelor.
- Cele două sisteme sunt complet izolate: un agent compromis nu poate apela endpoint-uri de user, și invers.
